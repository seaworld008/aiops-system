# 当前项目状态

> 更新时间：2026-07-16
> 状态：`SPEC_APPROVED / FAST_BUILD_IN_PROGRESS / RUNTIME_CLOSED`
> 当前集成基线：本文件所在的最新 `origin/main` 提交；最近完成 Batch：`M1C1-normalized-fact-contract-corrective`（PR #49）；当前 Batch：`M1E-atomic-page-commit-transaction`

## 当前结论

可运维资产、受控连接、事件/定时只读调查、受治理生产动作和生产发布运维的设计规范已经确认；八阶段范围仍以完整生产闭环为终点。2026-07-15 起采用[快速开发与真实验收计划](../superpowers/plans/2026-07-15-fast-development-validation-program.md)：189 个旧 Task 不再逐个重复发布级验证，而是聚合为 1–2 日 Batch，按 PR/G1、Batch/G2、Milestone/G3、系统代码完成后真实资格/G4 分层执行。

开发完成度与运行能力已经分离。当前可以把关闭态代码推进为 `BUILDING_CLOSED`/`BUILT_CLOSED`，也可在稳定 `Produces` 接口合并后并行后继轨道；这不等于阶段验收、Provider 可用或生产上线。所有未通过真实资格门的 Source、Connection、Capability、READ/WRITE admission、Action 和 Release 继续保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

阶段衔接固定采用不可变 Phase 6 READ baseline/handoff 加独立内容寻址的 Phase 7 Action platform successor；计划、授权、执行、验证和 Phase 8 release 都绑定同一双修订闭包。合法注册的 WRITE 增量不会篡改 READ 基线，任何未登记 WRITE surface 或闭包漂移都会关闭 admission。

调查端仅能追加 `PROPOSAL_ONLY` ActionProposal/Human Review Finding。ActionPlan 创建已锁定为经认证的人从完整 T/W/E/S URL Scope 发起，并在同一 serializable PostgreSQL transaction 内完成 Handoff Loader 可信重载、摘要/资格复验、其余事实解析和 `CreateInTx` 封存；Loader 前不得预读 Proposal，浏览器或模型提交的 Scope/授权事实不能成为真值源。

Phase 1 Task 1 的 `000015_assets_catalog` PostgreSQL 安全底座及 `M0-asset-domain-contract` 已通过 PR #34 squash merge 到 `origin/main@d933638`。M0 定向关闭了环境映射 P0 parity：数据库、Go 与 CSV/API 契约现在只接受 `SINGLE_ENVIRONMENT / EXPLICIT_ITEM_ENVIRONMENT`，明确拒绝旧 `MULTI_ENVIRONMENT`；原 corrective 的角色、ACL、不可变闭包、恢复和 admission 证据继续有效。

M0 同批完成 Task 2 的固定 Tenant 身份、Asset domain、validation/lifecycle、稳定 Repository 接口、MANUAL Profile/BindingDigest parity 和进程内 lease/fence 最小正确实现。过度测试约束已删除或改为真实行为契约；最终 reviewer 对 8 个已发现 P1 的修复全部判定 PASS，新增 P0/P1 为 0。受影响 Go/race、PostgreSQL enum up/down/up、Binding parity、schema/role admission、G1 与 G2 均通过；全仓 race、全部 Provider E2E、双实例恢复和重型里程碑门按计划记为 deferred G3/G4，不得解释为已通过。

M1A 已通过 PR #38 squash merge 到 `origin/main@f8aec40`：Pack 02 Task 3 的复合 Scope PostgreSQL Repository、MANUAL 原子治理写、receipt-first 幂等 replay、安全读模型以及 Observation/Type Detail/Audit/Outbox/Run 同事务闭包已成为关闭态代码。最终复核发现的一个 P1（冲突重放可借改写 SourceID 形成资格探针）已修复；修复后真实 PostgreSQL 18.4 受影响包、定向 race、G1/G2 重新全绿，同一 reviewer 最终 `APPROVE`。全仓 race、完整恢复、真实 Provider、HA、安全和浏览器/发布资格仍为 deferred G3/G4。

M1B 已通过 PR #41 squash merge 到 `origin/main@f9720ff`：现有 `assetcatalog.SourceReadRepository` 的 PostgreSQL 实现现在提供复合 Source Scope、完整 authority-set subset、restricted-empty、MANUAL 单 Environment usage、安全列投影、`source.id ASC` keyset/QueryDigest 和 exact current/published/last-success 指针。真实 PostgreSQL 18.4 受影响包、fresh G1/G2、代码地图和独立 P0/P1 复核均通过；Source mutation、Provider 和运行能力仍未开放。

M1C 已通过 PR #42 squash merge 到 `origin/main@ceca330`：`assetdiscovery` normalized facts/relations/freshness/provenance 与 `discoverysource` typed Runtime/opaque Checkpoint/Validation/closed `Page|Delay` 合同已成为稳定关闭态 `Produces`。pre-RED 审计修复了四处未定 ABI；最终复核又发现并关闭 Provider proof 可冒领 Broker cleanup/Gate availability code namespace 的 P1，修复后真实负例、两个受影响包、定向 race、fresh G1/G2 和同一 reviewer 复核全部通过。

M1D 已通过 PR #44 squash merge 到 `origin/main@661af40`：`internal/discoverycheckpoint` 现在提供固定九字段 typed AAD、AES-256-GCM sealed checkpoint、独立 HKDF/HMAC replay identity、进程内 retained keyring 与敏感序列化/日志关闭边界。九字段逐项 tamper、key rotation、missing retained key、随机 nonce、65,507-byte 上限、定向 race、fresh G1/G2 和独立 P0/P1 复核均通过；这仍只是关闭态 codec，不表示 Queue、Worker、Provider 或运行能力可用。

M1E0 已通过 PR #46 squash merge 到 `origin/main@4ddb644`：`000015` 的两个 relation digest equality rejection 现在只为 exact canonical-empty digest 提供例外，相同非空 digest、sequence、checkpoint、fence、exact receipt 与 deferred closure 继续 fail closed；corrected PostgreSQL 18.4 manifest SHA 已纳入 SchemaAdmission。真实连续空页、完整负向回滚矩阵、up/down/up、schema/role admission、fresh G1/G2 与独立 P0/P1 复核均通过。

M1C1 已通过 PR #49 squash merge 到 `origin/main@c427a6b`：`NormalizedItem.DisplayName` 已与 Asset/SQL 收敛为 256-byte 上限；`ObservedRelation` 现在显式携带结构校验后的 `CrossEnvironmentPolicyReferenceID`，同 Environment 禁止该值，cross Environment 必须 non-empty/valid；六元 relation identity 保持不变，reference 作为 present framed field 计入 `MaxPageBytes`。三个真实 RED、完整 GREEN 矩阵、两包 unit/race、fresh G1/G2 与独立 P0/P1 复核均通过。Opaque reference 仍只是 lookup key，不等于策略许可；M1E 必须用 locked SourceRevision resolver 取得 expected reference并 exact 比较。旧 M1E 未提交内部实现不作为输入，当前从 fresh 窗口恢复 [M1E 原子页提交](../superpowers/plans/2026-07-13-governed-operations/01-assets/13-m1e-page-commit-transaction.md)。Queue/Worker/Provider/生产装配继续 `NOT_STARTED`。

## 当前实施进度

Phase 1 Task 1 首轮 Red → Green → 独立安全复核结果仍是有效证据，范围严格限于生产资产目录的数据库基础：

- `000015` corrective 契约固定只拥有十张 Asset Catalog 表；新增的 `asset_source_revision_authorities` 是 Source Revision 的不可变权限 Environment 成员事实，其余九张保持首轮所有权。十表共同包含完整 Scope FK、不可变历史、Source Revision/Run/lease/fence/checkpoint、Observation/Relationship freshness domain、receipt/terminal closure、受保护 down 和生产 schema admission manifest。
- 首轮 schema admission 固定受审 PostgreSQL 18.4 catalog 摘要；corrective Up 已实现精确 35 个函数与 39 个触发器。逐签名 owner/ACL、deparse GUC、definition digest、直接 `pg_depend`、跨 locale C 排序、恢复后指纹与双实例恢复已通过 Steps 4–5 真库/race/独立复核。
- 真实 PostgreSQL 18.4 TLS 普通、race、在线兼容、双实例 dump/restore、恢复后 admission 与零 Skip 门均通过；full migration runner 和 Asset harness 只接受项目专用 `aiops_test` 控制库命名族，在其中创建 128 位随机物理数据库，并只清理已确认创建的数据库，不破坏共享 `public`。
- 首轮 `make test-integration` 六个 PostgreSQL 包和 `go test ./... -count=1` 全绿；当时的独立安全与 Task 1 验收审计均无未关闭 P1/P2/P3。

已合并 corrective 包含默认拒绝且可由 `000017/000019` 原位替换的 `asset_catalog_future_source_gate_admitted(asset_sources)`、收紧的 Opaque Reference 语法、authority child、typed-extension nullable pair、三摘要 PostgreSQL 重算、四角色 ABI、独立 migration/application DSN、schema/role admission 与恢复证明。环境映射枚举 parity 已由 M0 定向关闭，Task 1 其余验收范围不重开。Task 2 当前为 `BUILT_CLOSED`；K8S/AWX 仍保持 `UNAVAILABLE`。

Task 1 只建立后续实现所需的数据库安全底座。没有任何真实 Source Adapter、Catalog Repository/API、浏览器入口、Credential 获取或生产执行能力因此变为可用；Phase 1 继续保持 `IN_PROGRESS`，所有未逐类型验收的 Provider/Capability 继续 `UNAVAILABLE`。

## 已存在的代码事实

- Go 模块、Control Plane、Worker、READ/WRITE Runner、Executor 及调查/执行基础包已经存在。
- 生产部署基线仍到 `000014_read_evidence_clock_skew`；仓库 `main` 已包含尚未生产部署的 `000015_assets_catalog`。先前 Step 8 的缺失矩阵已闭合并重新独立验收；当前只对环境映射枚举 parity 做定向修正。
- 现有架构包含 OIDC、策略、Action/Execution、credential revocation、mTLS Runner Gateway、调查 Runtime/Target/Connector/Evidence 和 Temporal 编排基础。
- `000008` 的生产 WRITE 关闭约束仍是安全基线；在 Phase 7 的逐 Action 门禁正式验收前不得移除。
- `docs/architecture/implementation-blueprint-v3.md` 仍描述现有实现；V4 将在纵向实施过程中创建并最终成为新架构入口。

## 已完成的规划事实

- 已确认规范：[可运维资产、受控连接与受治理生产闭环设计](../superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md)
- 总实施计划：[Governed Operations Program](../superpowers/plans/2026-07-13-governed-operations-program.md)
- 快速构建与分层验证：[快速开发与真实验收计划](../superpowers/plans/2026-07-15-fast-development-validation-program.md)
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

当前范围共拆分为 **59 个任务包、189 个旧实施 Task**。它们是范围和最终证据清单；实际开发按快速计划聚合为 Batch，不再把 189 当作 189 次独立完整验收：

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
| 新资产目录与发现 | BUILT_CLOSED（M0/M1A/M1B/M1C/M1D/M1E0/M1C1）/ M1E BUILDING_CLOSED / UNAVAILABLE | 数据库底座、领域/接口/LeaseFence、治理 Repository/MANUAL、Source read、corrected discovery data-plane 合同、checkpoint Codec 与 repeated-empty relation-page corrective 已合并；M1E page commit 正在实现，Queue、Source mutation、API、前端与真实 Provider 门仍未完成 |
| Connection 修订/验证/发布 | NOT_STARTED | 等待 Phase 2 |
| VictoriaMetrics/Logs/Traces 全家桶 | NOT_STARTED | 等待 Phase 3 |
| 事件/定时主动只读调查 | NOT_STARTED | 等待 Phase 4 |
| Host/AWX/PostgreSQL 只读诊断 | NOT_STARTED | 等待 Phase 5 |
| HA 生产只读路径 | NOT_STARTED | 等待 Phase 6 |
| 四类初始受治理生产 Action | CLOSED | 等待 Phase 7 逐类型演练与 Canary |
| 生产发布与持续运维 | NOT_STARTED | 等待 Phase 8 |
| 新 React 前端 | NOT_STARTED | 前端应用平台架构已纳入确认规划；`web/` 与业务实现尚未开始，Phase 1 建骨架，此后随各阶段纵向交付 |

## 已知基线注意事项

当前共享主目录下存在用户拥有的嵌套 `.worktrees`；不得删除或修改。Phase 1 Task 1 及 corrective 均在模块根目录不包含嵌套 `.worktrees` 的外部隔离 worktree 中执行；首轮与 corrective 均已取得完整 Go/PostgreSQL/恢复证据，后者已通过重新独立验收。

实施分支新增 `000015` 与测试基础设施，但没有修改生产部署配置，也没有把该迁移描述为已在生产执行。

本机 PostgreSQL 18.4 TLS 测试依赖已预置彼此独立的 test-control、migration 和 application LOGIN 身份、随机密码及客户端证书；仓库只持久化三类变量名、外部文件布局、权限/角色边界与无 Secret wrapper，真实密码、私钥和完整 DSN 均留在 Git 外。为承载 Step 6 默认跨包并行门，项目外专用测试实例的 `max_connections` 已从原值 `30` 调整为 `100`，只重启该实例的 `aiops-postgres18` 容器；回滚恢复 `30` 并只重启同一容器。该容量设置、外部文件与测试实例均非生产配置，也未进入仓库 Git。

## 下一步

当前从最新 `origin/main@c427a6b` 执行 `M1E-atomic-page-commit-transaction`，按五文件任务包实现 package-private PostgreSQL projection helper 与 `PageCommitter` 原子页提交。它只消费已经合并的 M1A/M1C/M1D/M1E0/M1C1 稳定 `Produces`，固定 receipt-first、wrong-profile-before-Seal、single-Seal、bounded serializable retry、canonical page/relation identity、locked Revision Fact/relationship-policy resolver、one-transaction closure 与安全错误 vocabulary。

M1E G1/G2/独立复核通过并 squash merge 后，归档旧窗口并从最新 `origin/main` 创建 Queue PostgreSQL lifecycle Batch；Queue 公共 ABI、ClaimResult 与 sealed `LeaseFence` 只在真实消费点一起定值。所有这些关闭态 Batch 最多记为 `BUILT_CLOSED`，资产运行能力继续 `UNAVAILABLE`；G3/G4 的全仓 race、真实 Provider、HA、恢复、安全、浏览器和发布资格仍为 deferred。

任何阶段出现 Scope/身份/计划/Runtime/策略/Kill Switch/credential 漂移、依赖不可用、Secret 风险或结果不确定时，保持在最后已验收状态并停止升级，不得用人工口头确认替代持久证据。
