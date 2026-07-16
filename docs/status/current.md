# 当前项目状态

> 更新时间：2026-07-17
> 状态：`SPEC_APPROVED / FAST_BUILD_IN_PROGRESS / RUNTIME_CLOSED`
> 当前集成基线：本文件所在的最新 `origin/main`；最近完成 Batch：`M1L-source-revision-contract` Task 13（PR #77，代码提交 `2a66e8a`）与 `M1I-web-foundation-assets` Task 9（PR #76，代码提交 `8202a58`）；当前正在从该基线轮换 `M1I-asset-catalog-ui` Task 10 与 `M1L-source-authorization-http` Task 14

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

M1C1 已通过 PR #49 squash merge 到 `origin/main@c427a6b`：`NormalizedItem.DisplayName` 已与 Asset/SQL 收敛为 256-byte 上限；`ObservedRelation` 现在显式携带结构校验后的 `CrossEnvironmentPolicyReferenceID`，同 Environment 禁止该值，cross Environment 必须 non-empty/valid；六元 relation identity 保持不变，reference 作为 present framed field 计入 `MaxPageBytes`。三个真实 RED、完整 GREEN 矩阵、两包 unit/race、fresh G1/G2 与独立 P0/P1 复核均通过。Opaque reference 仍只是 lookup key，不等于策略许可；M1E 使用 locked SourceRevision resolver 取得 expected reference 并 exact 比较。

M1E 已通过 PR #53 squash merge 到 `origin/main@3f75809`：五个新文件实现 `PageCommitter`、package-private PostgreSQL projection helper 及 receipt-first 原子页提交，固定 wrong-profile-before-Seal、single-Seal、bounded serializable retry、canonical page/relation identity、locked Revision Fact/relationship-policy resolver、one-transaction closure 与安全错误 vocabulary。PR #52 先关闭 Observation ACL 契约冲突；同一独立 reviewer 发现并关闭 fingerprint collision 未 CAS `AMBIGUOUS`、bulk tombstone/restore 缺失逐资源 Audit/Outbox 两个 P1，最终无未关闭 P0/P1。真实 PostgreSQL 18.4 TLS、42501 权限矩阵、定向 race、受影响包 G2、fresh G1、边界/DLP/secret 检查均通过。Queue/Worker/Provider/生产装配继续 `NOT_STARTED/UNAVAILABLE/CLOSED`，全仓 race、真实 Provider、HA、恢复、完整安全、浏览器和发布资格仍为 deferred G3/G4。

Queue PostgreSQL lifecycle 已通过 PR #55 squash merge 到 `origin/main@7180993`：四个新文件冻结完整 Queue ABI、process-local sealed `ClaimResult` 与 bounded `CleanupProof` verifier boundary，并实现 claim/reclaim、strict heartbeat、cleanup intent/delay、validation/failure finalization、checkpoint lineage rollover 和 receipt-first terminal replay。真实 PostgreSQL 18.4 TLS application 身份随机顺序状态机、定向 race、受影响回归与 fresh G1/G2 均通过；独立 reviewer 首轮发现的 rollover 跨 fresh fence exact replay P1 已用真实 RED→GREEN 关闭，最终无剩余 P0/P1。Limiter、CleanupBroker transport、Worker、Provider 和生产装配仍为 `NOT_STARTED/UNAVAILABLE/CLOSED`，双实例 HA/恢复、PostgreSQL 重启、真实 Provider、完整安全/浏览器/发布资格继续 deferred G3/G4。

CleanupBroker boundary 已通过 PR #57 squash merge 到 `origin/main@3a3520c`：两个新文件提供 exact attempt 并发/响应丢失单 session、opaque attempt revoke、稳定 signed proof replay、`REVOKED|UNCERTAIN` fail-closed 语义、pointer/value serialization/logging 关闭边界，以及与 in-flight Open/Revoke/Verify 闭合的 Destroy 生命周期。规格、代码质量与独立 P0/P1 复核最终均 `APPROVE`；fresh G1、Queue/Broker G2、定向 race、Secret/import/两文件边界均通过。真实 Credential/Vault/Provider transport、Worker、生产装配、HA/恢复和 G3/G4 仍未完成，运行能力继续 `UNAVAILABLE/CLOSED`。

Limiter persistence C0 corrective 已通过 PR #59 squash merge 到 `origin/main@034d4e3`：`000015` 现在拥有 `asset_source_limit_buckets` 与 append-only `asset_source_limit_permits`，精确表达 Source/Workspace/Provider 三组 bucket、ACQUIRE/RELEASE/DELAY/EXPIRE receipt、响应丢失 replay、CAS、down 拆环和恢复语义；同批加入 runtime-only `SECURITY DEFINER asset_catalog_lock_exact_service_binding(...)` 及精确 ACL/admission。真实 PostgreSQL 18.4 TLS、定向 race、双实例恢复、两路独立复核、fresh G1/G2 均通过。该 corrective 只解除后继 Limiter/M1F 的持久契约阻塞，没有实现 Limiter Go runtime，运行能力继续 `UNAVAILABLE/CLOSED`。

M1F Mapping/Management 已通过 PR #60 squash merge 到 `origin/main@1a8e777`：九个精确文件实现 Task 5–6 的 `MappingRepository`、复合 `ResolveConflictScope`、关系/冲突/Binding 安全查询、serializable CAS/固定锁序/持久 receipt/Audit/Outbox 原子闭包、VIEWER 与 `ASSET_*` 权限，以及五个窄 Management 接口。C0 RED 覆盖跨 Tenant、缺 exact Environment binding、复合 Scope 重载、非 EXACT 和错误 If-Match；真实 PostgreSQL Mapping integration/race、受影响 unit/race、fresh G1/G2、代码地图和独立复核均通过，最终 P0/P1 为 0。OpenAPI、HTTP、Web、Source mutation、Worker、Provider 和生产装配仍未完成。

M1G Control Plane API 已通过 PR #62 squash merge 到 `origin/main@39053fb`：二十四个精确文件实现唯一 OpenAPI 3.1、匿名 no-store Browser Config、浏览器/API 分离 OIDC 校验、严格 JSON、强 ETag、签名 Cursor、RFC 9457、安全 DTO、资产/来源/关系/冲突/Binding handlers，以及只装配真实 PostgreSQL Management 并在启动和 readiness 持续执行 SchemaAdmission 的关闭态 Control Plane。可信 RED 覆盖 OpenAPI/安全原语/认证/Scope/DTO/依赖缺失；独立复核发现的 Source 查询参数未成对约束和缺失 SchemaAdmission 两项 P1 已关闭。受影响 unit/race、OpenAPI 生成、约 25 万次 strict JSON fuzz、fresh G1/G2、代码地图、Secret/Provider 与二十四文件边界均通过；GitHub 快速 `go` 55 秒通过。旧 credential Problem 缺 `trace_id` 与 Asset Catalog stable error 集缺少数据库不可用 sentinel 作为上游 C0 债务保留，相关能力继续 `UNAVAILABLE/CLOSED`。

M1H Discovery Limiter Runtime 已通过 PR #64 squash merge 到 `origin/main@2f05686`：三个新文件提供关闭态 `Limiter.Acquire/Release/Delay` ABI 与 PostgreSQL runtime，固定 exact Scope/Source/Run/Provider、`SOURCE→WORKSPACE→PROVIDER` 锁序、单个 `SERIALIZABLE READ WRITE` transaction、bucket CAS、append-only permit/terminal ledger、响应丢失 replay、过期 `EXPIRE` 恢复、Run lease/admission 重验和 exact installed Profile 验证。真实 PostgreSQL 18.4 TLS、定向 race、scoped G2、fresh G1、Secret/三文件边界和代码地图均通过；独立复核发现的 fresh Acquire admission 重验与 installed Profile parity 两项 P1 已关闭，最终无剩余 P0/P1。GitHub 快速 `go` 1 分钟通过。Worker、Provider、生产装配及 G3/G4 仍未完成，运行能力继续 `UNAVAILABLE/CLOSED`。

M1J Asset Catalog Unavailable C0 已通过 PR #66 squash merge 到 `origin/main@192ca04`：六个精确文件新增脱敏 `assetcatalog.ErrUnavailable`，只把明确连接、pool 和 PostgreSQL 系统可用性故障映射为 `503 asset_catalog_unavailable`；既有语义冲突继续 `409`，未知 SQLSTATE 或程序错误继续脱敏 `500`，不泄漏 SQLSTATE、数据库文本、DSN 或 endpoint。独立复核发现普通 `BeginTx` 错误被过宽归类为 503 的一个 P1，已以第二轮 RED→GREEN 修复；受影响 unit/race、scoped G2、fresh G1、Secret/六文件边界、代码地图及 GitHub 快速 `go` 48 秒均通过，最终 P0/P1 为 0。

M1I Session OpenAPI C0 已通过 PR #68 squash merge 到 `origin/main@c6ed29f`：四个精确文件为现有 authenticated `GET /api/v1/session` 发布唯一 `getSession` operation、全局 OIDC、`200/401/503` responses 与八字段 closed `Session` schema，并同步 exact path-count 和 hard-coded contract digest。可信 RED 证明缺 path、path count `13→14` 和旧 digest 漂移；受影响 OpenAPI/HTTP、fresh G1、Secret/四文件边界、commit-bound 代码地图及 GitHub 快速 `go` 1 分钟均通过，独立复核 P0/P1 为 0。该契约解除 Web Task 9 的 generated Session/Scope 入口阻塞，不表示浏览器能力已经实现或可用。

M1K Credential Problem Trace C0 已通过 PR #70 squash merge 到 `origin/main@113af87`：两个精确文件把 Credential Revocation handler 的全部 4xx/5xx Problem 响应迁移到已有 request-aware trace 投影，使响应体 `trace_id` 与 `X-Trace-ID` 一致，同时保持原有 status/code/detail、`WWW-Authenticate`、`no-store` 与 `nosniff` 语义。可信 RED 覆盖 manager 缺失、认证失败、路径/媒体类型/请求体错误、全部 manager error mapping 与未知 500；受影响 unit/race、fresh G1、Secret/两文件边界、commit-bound 代码地图及 GitHub 快速 `go` 1 分钟均通过，独立复核 P0/P1 为 0。该 corrective 只关闭既有 HTTP Problem 可追踪性债务，不开放 credential、资产或执行能力。

M1I TypeScript 工具链契约 corrective 已通过 PR #73 squash merge 到 `origin/main@690f84a`：24 个精确规划文件中的 25 处 TypeScript `7.0.2` 已统一为正式 peer intersection 的最高稳定版本 `5.9.3`；固定 `typescript-eslint@8.63.0`、`openapi-typescript@7.13.0`、Node 24 和 pnpm 10.34.0 的仓库外严格 peer graph 安装通过。版本基线同时记录 TypeScript 7 的正式升级入口，并禁止 `packageExtensions`、忽略 peer dependency、第二套 TypeScript 或手写 DTO 绕过。独立规格与 P0/P1 复核均通过，GitHub 快速 `go` 通过；该 corrective 只解除 Web Task 9 的工具链入口阻塞，不表示前端已经实现或可用。

M1L Source Revision Contract 已通过 PR #77 squash merge 到 `origin/main@2a66e8a`：六个精确文件实现 `CreateRevision/RequestValidation/Publish/Disable/RequestSync` 的 immutable Repository、复合 Scope、SERIALIZABLE、ETag/CAS、receipt-first replay、Audit/Outbox 与安全错误投影。MANUAL 使用 exact installed Profile 完成同步 Validation/Publication 闭包；非 MANUAL 在稳定引用解析器和后继 Adapter 尚未交付时保持 fail closed。PostgreSQL 18.4 Task 13 integration、领域/M1C/PostgreSQL 定向 race、fresh G1、DLP/Secret/边界与代码地图均通过；两轮独立复核最终 P0/P1 为 0。Task 14–16、真实 Provider、HA、恢复及 G3/G4 仍未完成，Source 能力继续 `UNAVAILABLE/CLOSED`。

M1I Web Foundation 已通过 PR #76 squash merge 到 `origin/main@8202a58`：五十九个精确文件建立唯一 `web/`、冻结 React/TypeScript/Vite 工具链、唯一生成类型、Browser Config→Keycloak PKCE→Session bootstrap、Scope/history、typed API、共享 Operation/UI，以及 Go 同源 SPA、CSP、路径隔离和 readiness fail-closed。独立复核发现的 TOCTOU、生产 API/Auth 注入、深链/dirty guard、终态 Operation、响应式、AbortSignal、网络旁路与 history Scope 漂移均以可信 RED→GREEN 关闭；最终 `pnpm check`、50/50 Vitest、受影响 Go race、fresh G1、bundle/Secret/边界与代码地图通过，P0/P1 为 0。真实 Keycloak/浏览器、Playwright/axe、HA、恢复及 G3/G4 仍 deferred，前端继续 `UNAVAILABLE/CLOSED`。

## 当前实施进度

Phase 1 Task 1 首轮 Red → Green → 独立安全复核结果仍是有效证据，范围严格限于生产资产目录的数据库基础：

- `000015` corrective 契约固定拥有十二张 Asset Catalog 表；除 Source/Revision/authority/Run/Observation/Asset/Type Detail/Conflict/Relationship/Binding 外，新增独立 Limiter bucket 与 permit/receipt truth。十二表共同包含完整 Scope FK、不可变历史、Source Revision/Run/lease/fence/checkpoint、Limiter CAS/replay、Observation/Relationship freshness domain、receipt/terminal closure、受保护 down 和生产 schema admission manifest。
- schema admission 固定受审 PostgreSQL 18.4 catalog 摘要；corrective Up 已实现精确 36 个函数与 45 个触发器。逐签名 owner/ACL、deparse GUC、definition digest、直接 `pg_depend`、跨 locale C 排序、恢复后指纹与双实例恢复已通过真库/race/独立复核。
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
- 前端应用平台架构已纳入确认规划并由 `M1I-web-foundation-assets` Task 9 落地为关闭态 Foundation：唯一 `web/` 采用 React 19.2.7 + TypeScript 5.9.3 + Vite 8.1.4 + TanStack，固定 `app → features → shared`、OpenAPI 唯一 DTO、服务端 `effective_actions`、Go 同源 SPA/API 与单 Control Plane 镜像 `/opt/aiops/web`；智能体验只通过 Evidence/Proposal/ActionPlan/Operation/Audit 受治理链呈现。Task 10 起只扩展纵向页面，不得重建认证、transport、Scope、状态仓库或第二套前端事实源。
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
| 新资产目录与发现 | BUILT_CLOSED（M0/M1A/M1B/M1C/M1D/M1E0/M1C1/M1E/Queue/CleanupBroker/Limiter C0/M1F/M1G/M1H/M1J/Session C0/Credential Trace C0/TypeScript C0/M1I Web Foundation/M1L Source Revision）/ Task 10、Task 14 BUILDING_CLOSED / UNAVAILABLE | Web Foundation 与 immutable Source Revision 已合并；正在轮换 Asset Catalog UI 与 Source authorization/OpenAPI/HTTP，Worker、ingestion 与真实 Provider 门仍未完成 |
| Connection 修订/验证/发布 | NOT_STARTED | 等待 Phase 2 |
| VictoriaMetrics/Logs/Traces 全家桶 | NOT_STARTED | 等待 Phase 3 |
| 事件/定时主动只读调查 | NOT_STARTED | 等待 Phase 4 |
| Host/AWX/PostgreSQL 只读诊断 | NOT_STARTED | 等待 Phase 5 |
| HA 生产只读路径 | NOT_STARTED | 等待 Phase 6 |
| 四类初始受治理生产 Action | CLOSED | 等待 Phase 7 逐类型演练与 Canary |
| 生产发布与持续运维 | NOT_STARTED | 等待 Phase 8 |
| 新 React 前端 | BUILT_CLOSED Foundation / BUILDING_CLOSED Asset UI / UNAVAILABLE | Task 9 Foundation 已合并；Task 10 只消费既有 generated Asset DTO 与共享 shell，建立 `/assets` 关闭态纵向页面，真实浏览器资格未通过前仍不可用 |

## 已知基线注意事项

当前共享主目录下存在用户拥有的嵌套 `.worktrees`；不得删除或修改。Phase 1 Task 1 及 corrective 均在模块根目录不包含嵌套 `.worktrees` 的外部隔离 worktree 中执行；首轮与 corrective 均已取得完整 Go/PostgreSQL/恢复证据，后者已通过重新独立验收。

实施分支新增 `000015` 与测试基础设施，但没有修改生产部署配置，也没有把该迁移描述为已在生产执行。

本机 PostgreSQL 18.4 TLS 测试依赖已预置彼此独立的 test-control、migration 和 application LOGIN 身份、随机密码及客户端证书；仓库只持久化三类变量名、外部文件布局、权限/角色边界与无 Secret wrapper，真实密码、私钥和完整 DSN 均留在 Git 外。为承载 Step 6 默认跨包并行门，项目外专用测试实例的 `max_connections` 已从原值 `30` 调整为 `100`，只重启该实例的 `aiops-postgres18` 容器；回滚恢复 `30` 并只重启同一容器。该容量设置、外部文件与测试实例均非生产配置，也未进入仓库 Git。

## 下一步

从最新 `origin/main@8202a58` 创建 fresh 可见窗口执行 `M1I-asset-catalog-ui` Task 10：只拥有 `web/src/features/assets/`、`web/src/app/router.tsx` 和两个既有 MSW fixture/handler 文件；消费已合并 generated Asset DTO、typed client、Scope/history、shared UI 与 `effective_actions`，实现 `/assets` 和 `/assets/$assetId` 的关闭态纵向切片。不得修改 OpenAPI、生成类型、后端、Foundation、status 或 Tasks 11–12；执行受影响 Web G2、fresh G1 和独立 P0/P1 复核后再提交 PR。

并行从最新 `origin/main@8202a58` 创建 fresh 可见窗口执行 `M1L-source-authorization-http` Task 14：只拥有 Source 权限/Management、唯一 OpenAPI、Source HTTP/router 与生成 `schema.d.ts`；消费已合并 SourceRevisionRepository，发布严格 Source/Revision/Run DTO、human/workload 身份隔离和服务端 `effective_actions`。不得修改 migration、Task 10 feature 文件、status、CSV/API ingestion 或 Worker；完成 C0 RED、Go/OpenAPI/generated parity、受影响 G2、fresh G1 和独立 P0/P1 复核后提交 PR。

Task 10 与 Task 14 文件所有权无重叠：前者只消费当前生成契约，后者是唯一 OpenAPI/generated owner；后继不得读取对方未提交内部实现。后续并发只在稳定 `Consumes/Produces` 已合并且 Batch 文件所有权不重叠时启动；所有关闭态 Batch 最多记为 `BUILT_CLOSED`，资产运行能力继续 `UNAVAILABLE`；G3/G4 的全仓 race、真实 Provider、HA、恢复、安全、浏览器和发布资格仍为 deferred。

任何阶段出现 Scope/身份/计划/Runtime/策略/Kill Switch/credential 漂移、依赖不可用、Secret 风险或结果不确定时，保持在最后已验收状态并停止升级，不得用人工口头确认替代持久证据。
