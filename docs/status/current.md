# 当前项目状态

> 更新时间：2026-07-15
> 状态：`SPEC_APPROVED / IMPLEMENTATION_IN_PROGRESS`
> 实施分支：`codex/governed-operations-assets`；已验收范围以本文“当前实施进度”和任务包 checkbox 为准

## 当前结论

可运维资产、受控连接、事件/定时只读调查、受治理生产动作和生产发布运维的设计规范已经确认；八阶段实施计划已经拆成阶段索引和小任务包。新规划以完整生产闭环为终点，不以 Demo、静态页面或生产只读试点为终点。

阶段衔接固定采用不可变 Phase 6 READ baseline/handoff 加独立内容寻址的 Phase 7 Action platform successor；计划、授权、执行、验证和 Phase 8 release 都绑定同一双修订闭包。合法注册的 WRITE 增量不会篡改 READ 基线，任何未登记 WRITE surface 或闭包漂移都会关闭 admission。

调查端仅能追加 `PROPOSAL_ONLY` ActionProposal/Human Review Finding。ActionPlan 创建已锁定为经认证的人从完整 T/W/E/S URL Scope 发起，并在同一 serializable PostgreSQL transaction 内完成 Handoff Loader 可信重载、摘要/资格复验、其余事实解析和 `CreateInTx` 封存；Loader 前不得预读 Proposal，浏览器或模型提交的 Scope/授权事实不能成为真值源。

Phase 1 Task 1 的首轮 `000015_assets_catalog` PostgreSQL 基础已在隔离实施分支通过原验收，但 Task 2 入口预检先发现 K8S/AWX 默认关闭逻辑缺少后继迁移可安全替换的 gate seam，随后契约审计又确认 authority membership 仅有 digest、typed-extension 两帧无持久列、direct SQL 摘要不可重算，以及 Source 读/管理接口实施任务不闭合。Task 1 因此已诚实回开 Steps 1–7 以重新执行 corrective RED→最小实现→完整验证，并把 Step 8 改为完成后的独立复核/验收；Step 1 的八组独立 RED、exact-ten ownership 与两项 stale-contract RED 已通过独立测试质量复核。Step 2 已在三身份 PostgreSQL 18.4 TLS 真库上完成单事务 Up/空 Down、十表/35 函数角色 admission，以及由独立 Go 字节 oracle 验证的 Authority N+2、SourceDefinition v2 六帧、BindingDigest 20 帧闭包；期间修正了锁前角色 preflight 和非法 `pg_catalog.coalesce`。Step 3 已在同一真库上完成十表 DELETE/TRUNCATE、Authority/Revision/Observation/TypeDetail 不可变、完整 Asset 生命周期矩阵、身份/version/server timestamp 及索引/Run shape 的 race 门。Step 4 已完成 18 表 NOWAIT guarded down、精确 predecessor ACL/shared-surface 恢复、在线兼容、双 admission、`pg_depend`/C 排序 manifest 与 hostile schema/TEMP shadow race 门。原 Step 5 已修复旧 fixture 的 Source/初始 Revision/Authority 同事务闭包与真实三摘要，完成 18 成员逐项 NOWAIT/释放重试和 live `pg_locks` 观察，并在不同 system identifier/OID 的 PostgreSQL 18.4 双实例上以非超级用户完成 custom dump/单事务 restore、恢复后双 admission、12 表 Hash、35 FK、不可变性及九类漂移门；原 Step 6 六包并行 race 与原 Step 7 提交 `d557237` 也已完成。Step 8 独立复核仍以 `REJECT/P1` 拒绝验收：corrective Profile/authority/digest/opaque/typed/future-hook 只有静态解析与部分 MANUAL 正向真库证据，缺少契约要求的持久 PostgreSQL 18.4 负向/阶段矩阵。按 finding 已回开 Steps 1/5/6/7，当前只补齐该测试证据；Step 2–4 仅在新测试暴露实现缺陷时回开。Task 2 Green 继续暂停；这不等于 Phase 1 已完成，更不等于生产部署。后续 Source、API、OpenAPI、前端与真实 Provider E2E 均未实现，因此不能宣称资产控制平面、VictoriaMetrics 全家桶、主机/PostgreSQL 诊断、主动调查、受治理写操作或新前端已经上线。

## 当前实施进度

Phase 1 Task 1 首轮 Red → Green → 独立安全复核结果仍是有效证据，范围严格限于生产资产目录的数据库基础：

- `000015` corrective 契约固定只拥有十张 Asset Catalog 表；新增的 `asset_source_revision_authorities` 是 Source Revision 的不可变权限 Environment 成员事实，其余九张保持首轮所有权。十表共同包含完整 Scope FK、不可变历史、Source Revision/Run/lease/fence/checkpoint、Observation/Relationship freshness domain、receipt/terminal closure、受保护 down 和生产 schema admission manifest。
- 首轮 schema admission 固定受审 PostgreSQL 18.4 catalog 摘要；corrective Up 已实现精确 35 个函数与 39 个触发器。逐签名 owner/ACL、deparse GUC、definition digest、直接 `pg_depend`、跨 locale C 排序、恢复后指纹与双实例恢复已通过 Steps 4–5 真库/race/独立复核。
- 真实 PostgreSQL 18.4 TLS 普通、race、在线兼容、双实例 dump/restore、恢复后 admission 与零 Skip 门均通过；full migration runner 和 Asset harness 只接受项目专用 `aiops_test` 控制库命名族，在其中创建 128 位随机物理数据库，并只清理已确认创建的数据库，不破坏共享 `public`。
- 首轮 `make test-integration` 六个 PostgreSQL 包和 `go test ./... -count=1` 全绿；当时的独立安全与 Task 1 验收审计均无未关闭 P1/P2/P3。

当前 corrective 已新增默认拒绝且可由 `000017/000019` 原位替换的 `asset_catalog_future_source_gate_admitted(asset_sources)`、收紧 Opaque Reference 数据库语法、加入 `asset_source_revision_authorities` 与 typed-extension nullable pair、由 PostgreSQL 重算 Source definition/authority/binding 三类摘要、冻结并验收 deployment-preprovisioned `aiops_migrator/aiops_schema_owner/aiops_control_plane_runtime/aiops_control_plane_workload` 四角色 ABI 与独立 migration/application DSN，并更新 schema/role admission manifest 和恢复证明。Step 8 的 P1 已回开 Steps 1/5/6/7；缺失真库矩阵闭合并重新验收前不得进入 Task 2 Green，K8S/AWX 仍保持 `UNAVAILABLE`。

Task 1 只建立后续实现所需的数据库安全底座。没有任何真实 Source Adapter、Catalog Repository/API、浏览器入口、Credential 获取或生产执行能力因此变为可用；Phase 1 继续保持 `IN_PROGRESS`，所有未逐类型验收的 Provider/Capability 继续 `UNAVAILABLE`。

## 已存在的代码事实

- Go 模块、Control Plane、Worker、READ/WRITE Runner、Executor 及调查/执行基础包已经存在。
- 生产基线迁移仍到 `000014_read_evidence_clock_skew`；隔离实施分支包含尚未部署的 `000015_assets_catalog` corrective 实现与提交 `d557237`。Step 8 已因缺失持久真库负向/阶段矩阵 `REJECT/P1`，当前回到 Step 1 测试证据纠正；最终验收尚未恢复。
- 现有架构包含 OIDC、策略、Action/Execution、credential revocation、mTLS Runner Gateway、调查 Runtime/Target/Connector/Evidence 和 Temporal 编排基础。
- `000008` 的生产 WRITE 关闭约束仍是安全基线；在 Phase 7 的逐 Action 门禁正式验收前不得移除。
- `docs/architecture/implementation-blueprint-v3.md` 仍描述现有实现；V4 将在纵向实施过程中创建并最终成为新架构入口。

## 已完成的规划事实

- 已确认规范：[可运维资产、受控连接与受治理生产闭环设计](../superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md)
- 总实施计划：[Governed Operations Program](../superpowers/plans/2026-07-13-governed-operations-program.md)
- 小文档入口：[Governed Operations Production Program](../superpowers/plans/2026-07-13-governed-operations/README.md)
- 覆盖追踪：[规范到实施计划覆盖矩阵](../superpowers/plans/2026-07-13-governed-operations/coverage-matrix.md)
- 版本基线：[生产规划版本基线](../superpowers/plans/2026-07-13-governed-operations/version-baseline.md)
- 前端应用平台架构已纳入确认规划：唯一 `web/` 采用 React 19 + TypeScript 7 + Vite 8 + TanStack，固定 `app → features → shared`、OpenAPI 唯一 DTO、服务端 `effective_actions`、Go 同源 SPA/API 与单 Control Plane 镜像 `/opt/aiops/web`；智能体验只通过 Evidence/Proposal/ActionPlan/Operation/Audit 受治理链呈现。该项仍是规划事实，`web/` 与新 React 业务实现继续为 `NOT_STARTED`。
- Phase 5 已确认但尚未实施的安全契约：[AWX Host Identity Enrollment](../contracts/awx-host-identity-enrollment-v1.md)、[AWX Governed Launch Admission](../contracts/awx-governed-launch-admission-v1.md)、[Host Identity Attestor](../contracts/host-identity-attestor-v1.md)。它们只修正后继阶段接口，Host/AWX/PostgreSQL 实现仍为 `NOT_STARTED`。

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
| 新资产目录与发现 | IN_PROGRESS | Task 1 corrective 的实现提交为 `d557237`，但 Step 8 已因缺失 Profile/authority/digest/opaque/typed/future-hook 持久真库矩阵 `REJECT/P1`，Steps 1/5/6/7 已回开；旧 fixture/Recovery、race、双实例恢复和六包并行门证据仍保留，但不能替代缺失矩阵。Task 2 起的领域、Repository、Source、API、前端与生产门仍未完成，运行能力保持 `UNAVAILABLE` |
| Connection 修订/验证/发布 | NOT_STARTED | 等待 Phase 2 |
| VictoriaMetrics/Logs/Traces 全家桶 | NOT_STARTED | 等待 Phase 3 |
| 事件/定时主动只读调查 | NOT_STARTED | 等待 Phase 4 |
| Host/AWX/PostgreSQL 只读诊断 | NOT_STARTED | 等待 Phase 5 |
| HA 生产只读路径 | NOT_STARTED | 等待 Phase 6 |
| 四类初始受治理生产 Action | CLOSED | 等待 Phase 7 逐类型演练与 Canary |
| 生产发布与持续运维 | NOT_STARTED | 等待 Phase 8 |
| 新 React 前端 | NOT_STARTED | 前端应用平台架构已纳入确认规划；`web/` 与业务实现尚未开始，Phase 1 建骨架，此后随各阶段纵向交付 |

## 已知基线注意事项

当前共享主目录下存在用户拥有的嵌套 `.worktrees`；不得删除或修改。Phase 1 Task 1 及 corrective 均在模块根目录不包含嵌套 `.worktrees` 的外部隔离 worktree 中执行；首轮已取得完整 Go/PostgreSQL/恢复基线，corrective 必须重新取得同等级证据。

实施分支新增 `000015` 与测试基础设施，但没有修改生产部署配置，也没有把该迁移描述为已在生产执行。

本机 PostgreSQL 18.4 TLS 测试依赖已预置彼此独立的 test-control、migration 和 application LOGIN 身份、随机密码及客户端证书；仓库只持久化三类变量名、外部文件布局、权限/角色边界与无 Secret wrapper，真实密码、私钥和完整 DSN 均留在 Git 外。该事实仅代表可执行的本地真实数据库测试前提，不代表生产数据库已部署。

## 下一步

继续按 [当前任务包](../superpowers/plans/2026-07-13-governed-operations/01-assets/01-schema-domain.md) checkbox 收口 Phase 1 Task 1：针对 Step 8 的唯一 P1，先在 Step 1 补齐持久 PostgreSQL 失败矩阵并独立复核测试质量，再完成 Step 5 真库矩阵、Step 6 六包并行回归与 Step 7 追加提交；若测试暴露实现缺陷，回开其所属 Step 2–4。随后重新执行 Step 8 独立验收，只有验收并形成独立文档提交后，才按 [Phase 1 索引](../superpowers/plans/2026-07-13-governed-operations/01-assets/README.md) 进入 Task 2 RED/Green。Phase 1 未验收前不进入 Phase 2。

任何阶段出现 Scope/身份/计划/Runtime/策略/Kill Switch/credential 漂移、依赖不可用、Secret 风险或结果不确定时，保持在最后已验收状态并停止升级，不得用人工口头确认替代持久证据。
