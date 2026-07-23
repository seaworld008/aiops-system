# 01 — 资产目录、真实发现来源与 Control Plane

本目录把 Phase 1 拆成 11 个生产任务包。它是[受治理运维能力总计划](../../2026-07-13-governed-operations-program.md)的第一阶段，产品、安全和前端语义以[已确认设计规范](../../../specs/2026-07-13-operational-assets-controlled-access-design.md)为准；快速构建的 Batch、并发和验证时机由[快速开发与真实验收计划](../../2026-07-15-fast-development-validation-program.md)统一覆盖。

本阶段的终点不是枚举、假 Provider、静态页面或 Demo：它建立十二表 PostgreSQL 事实（含不可变 Source Revision 权限 Environment 子表，以及独立 Limiter bucket 与 permit/receipt truth）、不可变 Source Revision、真实 CSV/API/CMDB/vSphere/Proxmox/OpenStack/AWS/Azure/GCP 协议适配、独立 Discovery Worker、HA lease/fence、加密 checkpoint、持久背压、逐 Provider gate，以及真实 OIDC/OpenAPI、Go 同源 SPA、类型化应用平台和 Overview。它仍不开放目标系统写操作；项目最终通过 Phase 7/8 的不可变 ActionPlan、策略、重新认证、人工审批、短凭据、类型化执行、独立验证、对账/回滚/升级与审计形成生产闭环。

## 产品依赖与最终验收顺序

1. [01-schema-domain.md](./01-schema-domain.md) — 创建 `000015_assets_catalog` 十二张表、Source Revision 权限 Environment/Run/Fence/Checkpoint、Limiter bucket/permit receipt 约束与稳定领域接口。
2. [02-repository-discovery.md](./02-repository-discovery.md) — 实现 Scope Repository、append-only Observation、provenance、tombstone/恢复和原子 checkpoint 投影。
3. [03-mapping-auth-api.md](./03-mapping-auth-api.md) — 实现关系/冲突/Service Binding、Browser/API OIDC 边界、runtime Browser Config、OpenAPI/HTTP 基线和真实 Control Plane 装配。
4. [04-web-foundation-assets.md](./04-web-foundation-assets.md) — 建立唯一 `web/`、`app → features → shared`、真实浏览器 OIDC、typed API/shared Operation/治理 UI、Go SPA、资产/映射/来源基线和持久前端 Foundation 规范。
5. [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md) — 实现 Source `draft→canonical revision→validate→publish/disable→sync`、权限/OpenAPI/effective_actions、CSV 与 mTLS API ingestion、六步 Source 向导。
6. [06-source-external-cmdb.md](./06-source-external-cmdb.md) — 实现固定 External CMDB Catalog v1 协议；Task 18A 只拥有 Provider paging/checkpoint，Task 18B 在 Pack 09 provider-neutral Worker core 合并后只拥有 CMDB durable reconciliation/lifecycle integration 和唯一 neutral metadata descriptor，Task 19A 单独装配 Control Plane profile/validation admission并把 non-MANUAL publication 保持关闭；reachability docs、capability harness、pre-A2a exact-2、manager evidence sync与global routine ACL exact-11 contract + status sync已合并，PR #153 exact9也已合并。截止2026-07-23仅冻结pre-A2a identity-FK fixture compatibility exact9B docs-only合同并暂停开发，test-only实现仍`NOT_STARTED`；恢复后须从届时最新`origin/main`新建fresh独立corrective并完成RED→GREEN/复核/PR/merge，fresh Task 19A2a exact12才可冻结 exact 3+23、`000015` owned exact-38 与 application-schema global exact-110 ABI；post-A2a exact-2 validation corrective 合并后 Task 19A2b/19A2c 再依次实现 persistence/current trust rechecks 与隔离 sealer/admitter connector、复用 Task 28A Worker seam 的私有 API/production，Task 19B 才拥有 CMDB canary/evaluator/AdmitGate operating proof。
7. [07-source-vsphere.md](./07-source-vsphere.md) — Task 21A 只在 Task 28A 同一 claim/AttemptSession/BoundRuntime 内实现 govmomi SOAP bounded full snapshot；Task 21B0 先建立独立 PropertyCollector session-continuity authority，Task 21B 才实现跨 Run delta、leave/soft-delete 与 HA resume，随后才允许 vCenter canary 和 gate。
8. [08-source-proxmox-openstack-cloud.md](./08-source-proxmox-openstack-cloud.md) — 实现 Proxmox、OpenStack、AWS、Azure、GCP 五个独立计算资产 Provider/gate。
9. [09-discovery-worker-ha-e2e.md](./09-discovery-worker-ha-e2e.md) — Task 27 只冻结自身已合并的 PostgreSQL Queue/process-local CleanupBroker/Limiter，M1E 继续唯一拥有既有 PageCommitter ABI/SQL；Task 28A 先交付 provider-neutral Worker core/claim-runtime seam，Task 28B 再交付 recoverable cleanup-session transport/same-attempt authority，但它只恢复 exact attempt cleanup，不拥有 vSphere PropertyCollector continuity；Task 28C 才拥有 registry/production constructor/`cmd/discovery-worker`，Task 29A 只产 two-worker HA/cleanup/restart/response-loss receipt 与低基数 metrics，Task 29B 最后聚合已完成 per-source gate/canary/HA receipts。
10. [10-overview-control-room.md](./10-overview-control-room.md) — 闭合 `/overview` 安全聚合 API/UI，分维显示 Assets/Sources/Connections/Investigations/Actions/Releases，未实现项显式 `NOT_STARTED/UNAVAILABLE`。
11. [11-e2e-docs.md](./11-e2e-docs.md) — 完成指标、真实 Keycloak/PostgreSQL/Playwright、视觉/axe/安全、CI、备份恢复、HA、持久文档和 Phase 1 签名验收。

快速构建桥接任务包 [12-m1e0-relation-page-corrective.md](./12-m1e0-relation-page-corrective.md) 已由 PR #46 关闭 fixed canonical empty relation digest 与 `000015` trigger 的 C0 冲突；[14-m1c1-normalized-fact-contract-corrective.md](./14-m1c1-normalized-fact-contract-corrective.md) 已由 PR #49 关闭 normalized fact/Asset/SQL parity 与 page-byte accounting；[13-m1e-page-commit-transaction.md](./13-m1e-page-commit-transaction.md)、Queue lifecycle、CleanupBroker 与 Limiter runtime 已由 PR #53/#55/#57/#64 分别合并并保持运行能力关闭。External CMDB Task 18A paging/checkpoint 已由 PR #98 合并并由 PR #99 修正 complete-checkpoint next-run restart；这仍不是 Task 18 durable lifecycle、Worker 或 gate 完成证据。

Task 18B 与 Task 27/28 的权威顺序现固定为：已合并 PageCommitter/Queue/process-local CleanupBroker/Limiter → [Task 28A provider-neutral Worker core](./09-discovery-worker-ha-e2e.md#task-28a-provider-neutral-worker-core-and-claim-runtime-seam) → [External CMDB Task 18B](./06-source-external-cmdb.md#task-18b-external-cmdb-durable-reconciliation-and-lifecycle-integration) provider-specific 真库集成 + neutral descriptor → [Task 28B recoverable session transport](./09-discovery-worker-ha-e2e.md#task-28b-recoverable-cleanup-session-transport-and-attempt-authority) → [Task 28C production](./09-discovery-worker-ha-e2e.md#task-28c-production-constructor-and-provider-registry)。已合并 Task 28C/19A 后，Source Gate successor contract 严格串行为 `reachability docs corrective → manager exact-3 contract sync → source-gate capability-identity harness C0 → pre-A2a exact-2 routine/test-boundary corrective → manager exact-3 evidence sync → global routine ACL exact-11 contract + status sync → pre-A2a formal-fixture compatibility exact-9 corrective → pre-A2a identity-FK fixture compatibility exact-9B docs-only contract checkpoint → [DEVELOPMENT_PAUSED] → resumed fresh test-only identity-FK fixture corrective → fresh Task 19A2a exact-12 → post-A2a exact-2 validation corrective → Task 19A2b → Task 19A2c → Task 29A → Task 19B → Task 29B`；具体入口见 [pre-A2a/Task 19A2a/19A2b/19A2c/19B](./06-source-external-cmdb.md) 与 [Task 29A/29B](./09-discovery-worker-ha-e2e.md)。PR #152 exact11与PR #153 exact9已按序合并，PR #153基线精确为`main@c0b620e6fff9de0b746504f5fb7231fcb4a213c4`、tree`0af13374448f1386593291631e10a07add41440b`；其后fresh formal A2a确认合法top-level FK报`unreviewed gate-evidence ALTER`、合法inline named FK报`unreviewed gate-evidence table element`并保持`STOPPED/NOT PASS`。截至2026-07-23，本轮exact9B只冻结exact8 docs合同为暂停检查点，原Phase B test-only实现永久停止于本轮并保持`NOT_STARTED`，不是本交付；最终formal合同仍要求唯一named `asset_sources_gate_evidence_run_fk` exact four-column `DEFERRABLE INITIALLY DEFERRED` FK，source/reference order、table/schema和mapping精确，digest/expiry不得入identity，baseline无FK且formal→baseline→formal重建后重验。inline named constraint仍是另一合法创建表达；missing/partial/duplicate、wrong/quoted alias name、wrong columns/order/table/schema、6-column、wrong deferral、dynamic DDL、除唯一精确top-level `ALTER TABLE public.asset_sources ADD CONSTRAINT asset_sources_gate_evidence_run_fk`创建语句外的任何ALTER、后续DROP/VALIDATE/rename/disable lifecycle、extra constraint/up-down mismatch全部fail closed；不得收窄PR #153 auxiliary、global exact72/110、owned exact38、ACL/owner/grantor/grantability/C-order/down manifest或原negative matrix；A2a exact12禁止修改该helper。predecessor 基线 direct grant 为0而normalized PUBLIC exact72；future fresh A2a up仍必须消费Pack06唯一exact72 manifest与production digest，新增内容寻址、owner-grantor/non-grantable的runtime→predecessor exact72 direct manifest，down先精确撤销再恢复PUBLIC72。三批 A2 files 分别12/11/23 files，由fresh window独立真实G2/PR/merge且两两零重叠；恢复后的唯一入口是从届时最新`origin/main`新建fresh、独立test-only identity-FK fixture corrective并完成RED→GREEN、完整验证、独立复核、PR/merge，之后才允许fresh A2a。停止的`cb00`及其他旧dirty/stopped A2a worktree/WIP/snapshot不能反向成为ABI事实源，任何未完成实现不提交、不合并。19A2c必须复用唯一Task28A loop，Task29A seam不足时先做冻结corrective。docs-only exact9B不改变completion、checkbox、G2/G4或能力，所有Source/Provider/Worker保持`NOT_STARTED/UNAVAILABLE/CLOSED`。

vSphere 的独立 closed DAG 固定为：[Task 28A](./09-discovery-worker-ha-e2e.md#task-28a-provider-neutral-worker-core-and-claim-runtime-seam) → [Task 21A same-attempt full snapshot](./07-source-vsphere.md#task-21a-same-attempt-bounded-full-inventory-and-complete-snapshot-closure)；随后 Task 21A + [Task 28B](./09-discovery-worker-ha-e2e.md#task-28b-recoverable-cleanup-session-transport-and-attempt-authority) → [Task 21B0 resident authority](./07-source-vsphere.md#task-21b0-vsphere-propertycollector-session-continuity-authority-c0-prerequisite) → [Task 21B delta/leave/HA](./07-source-vsphere.md#task-21b-cross-run-incremental-updates-leavesoft-delete-and-ha-safe-resume) → Task 28C vSphere registry row → Task 29A vSphere-specific HA evidence → [Task 22 gate/canary](./07-source-vsphere.md#task-22-vsphere-availability-gate-non-production-vcenter-canary-and-uioperations-proof) → Task 29B vSphere matrix row。Task 21A 可独立合并但能力保持关闭；21B0/21B 未真实完成前，registry、gate、canary、HA receipt和matrix都不得消费 vSphere 为 available。

存在前置依赖的代码只能消费已合并的稳定 `Produces` 接口。快速构建可按覆盖计划聚合 2–4 个相关旧 Task，并在接口冻结后并行 Provider/Web 轨道；任务包顺序继续约束 Phase 1 最终验收，不再强制每个 checkbox 独立 Red/Green/commit。C0 契约保留定向 RED，所有延后的真库、HA、恢复、安全、真实 Provider 与 E2E 证据必须在 G3/G4 补齐，补齐前能力保持 `UNAVAILABLE`。

## Consumes

- `main@ad50d9f` 的 Go/Control Plane/Worker/READ-WRITE Runner/调查执行安全基线。
- 已确认规范的 Scope、资产生命周期、字段所有权、来源类型、公共 API、权限、前端视觉/交互和安全不变量。
- 既有 `services`、`service_bindings`、`integrations`、`audit_records`、`outbox_events` 与 OIDC/Scope 契约；不解释未知 JSONB 为运行能力。
- 已有 `workerbootstrap`、`securemanifest`、PostgreSQL Outbox/lease 安全模式；新 Worker 复用原则但不复用 WRITE 授权。

## Produces

- `assetcatalog.Scope`、`AssetLocator`、`Reader.Get(context.Context, AssetLocator) (Asset,error)` 和 `assets UNIQUE (tenant_id,workspace_id,environment_id,id)`。
- 稳定 `asset_sources` + append-only/content-addressed `asset_source_revisions`，以及 fenced Run、encrypted checkpoint、独立 `asset_source_limit_buckets`/append-only `asset_source_limit_permits`、Observation/provenance、Asset/Conflict/Relationship/Binding 事实。
- `source_revision` 唯一表示 Source definition revision；Provider 事实新鲜度用 profile-locked `FreshnessCandidate` 与 append-only Observation chain 持久，不同 Run 可追加同一未变事实，同 Run 漂移重放、时间/序列回退或碰撞整页关闭。
- `SourceRevisionRepository`、`discoverysource.Provider`、已合并 `discoveryqueue.Queue`；Task 28A 唯一产生 provider-neutral `discoveryworker.Worker`/claim-runtime seam，Task 28B 唯一产生 fixed-mTLS recoverable cleanup-session transport/same-attempt authority，但不产生 vSphere PropertyCollector continuity；Task 21B0/21B 分别唯一产生 vSphere resident authority 与 cross-Run delta/leave/HA contract；Task 28C 唯一产生 exact Provider registry、production constructor、observer/decorator seam 与真实 `cmd/discovery-worker`；Task 19A2a/19A2b/19A2c 依次唯一产生 qualification schema/domain/admission、persistence/runtime rechecks、复用唯一 Worker loop 的 fixed workload API + immutable verifier registry/sole sink+signer，Task 29A/各 Provider gate/Task 29B 依次只产 HA receipt+real-binary metrics、per-source canary+decision、final matrix。
- 严格 Control Plane OpenAPI、no-store closed-schema `GET /api/v1/browser-config`、`ASSET_*`/`ASSET_SOURCE_*` 权限、`effective_actions`、签名 Cursor、ETag/Idempotency/RFC 9457 和唯一生成 TypeScript 契约。
- 唯一 `web/` 壳层和 `app → features → shared` 模块边界、仅 `shared/api` 的类型化 transport、共享 Operation/治理 UI、Scope-aware 状态所有权、Go 同源 SPA，以及 `/overview`、`/assets`、`/asset-mappings`、`/asset-sources` 与 Source revision wizard；持久设计文档 `foundation-assets.md`、`asset-sources.md`、`overview.md`。
- 逐 Provider 正向/负向/真实协议/非生产 canary/HA/DLP/rate-limit/checkpoint/delete-recovery 证据和独立 `AVAILABLE` gate。
- Phase 2 可消费的 exact Asset/Source identity、Scope、lifecycle、mapping、published Source revision 和前端/API 扩展入口。

## 锁定边界

| 项目 | 锁定值 |
|---|---|
| Go | `go 1.26` / `toolchain go1.26.5` |
| PostgreSQL | 18.4 或更新 18.x |
| 迁移 | `000015_assets_catalog` |
| 表归属 | `asset_sources`、`asset_source_revisions`、`asset_source_revision_authorities`、`asset_source_runs`、`asset_source_limit_buckets`、`asset_source_limit_permits`、`asset_observations`、`assets`、`asset_type_details`、`asset_conflicts`、`asset_relationships`、`service_asset_bindings` |
| 去重键 | `(tenant_id,workspace_id,source_id,provider_kind,external_id)` |
| 前端 | `web/`；Node 24、pnpm 10.34.0、React 19.2.7、TypeScript 5.9.3、Vite 8.1.4、TanStack Router/Query/Table、RHF/Zod、Radix、lucide-react、CSS Modules |
| OIDC | Keycloak Server 26.6.3；`keycloak-js` 26.2.4；Browser client `control-plane-web`、API audience `aiops-control-plane`；Authorization Code + PKCE、`login-required`、Token 仅内存 |
| Browser Config | 匿名 `GET /api/v1/browser-config`；closed schema + `no-store`；只含公开 OIDC、API base path 和 build metadata；缺失/畸形 fail closed |
| 契约 | `api/openapi/control-plane-v1.yaml` → `web/src/shared/api/schema.d.ts`；仅 `shared/api` 发网络请求并使用 generated `paths/operations` |
| 生产拓扑 | Go 同一进程/Origin 服务 API 与 `/opt/aiops/web`；单 Control Plane 镜像，无 Node/Vite server、独立 Web workload、Next/Remix/BFF/微前端 |
| 生产状态 | PostgreSQL + 真实 OIDC + 真实 Discovery Worker/Provider；fake/MSW 仅测试 |

`Source Revision` 内容在创建后不可修改；成功路径固定为 `DRAFT → VALIDATING → VALIDATED → PUBLISHED → SUPERSEDED`，失败路径为 `VALIDATING → REJECTED`，同一不可变内容可通过新的 Validation Run 重新进入 `VALIDATING`，但 `REJECTED` 不能直接发布。只有 exact `MANUAL/MANUAL_V1/MANUAL_V1` publication 可直接进入无 pointer 的 `AVAILABLE`；其他 exact non-MANUAL publication 固定落在 `PUBLISHED + UNAVAILABLE`，mixed/missing Profile 边界 fail closed。fixed workload-only qualification 的 final transaction 只封存零 Catalog projection 的 signed safe receipt并保持 Source pointer `NULL`/gate closed，后继唯一 serializable `AdmitGate` transaction 才能进入 `AVAILABLE`。普通 `RequestSync`/data claim 在此之前仍拒绝。Source 可用需 exact `ACTIVE + PUBLISHED + AVAILABLE`；Asset 进入运行还需 `EXACT + ACTIVE`。来源 gate、Asset lifecycle、Connection publication 和 Capability availability 不得相互代替。

## 阶段内稳定数据契约

- Source/Asset revision 在 PostgreSQL、Go、OpenAPI 和生成 TypeScript 中统一为 `int64`。`Asset.LastSourceRevision` 对应 `assets.last_source_revision`。
- `SourceRevision.BindingDigest() == CanonicalRevisionDigest`。`.v1` 固定 20 个 `FramedTupleV1` 帧：domain、Tenant/Workspace/Source/Revision、Provider/Profile definition digest、Integration、sync、三个 Opaque Reference、authority digest、四个 rate/backpressure 整数、Profile、schedule、typed-extension code/digest；无 extension 时最后两帧也必须为 `NULL`。`source_definition_digest` 不能吸收或替代 extension/binding digest，所有 SHA-256 以 32 raw bytes 入帧。
- `asset_source_revision_authorities` 是 1–100 个 same-Scope Environment membership 的唯一事实源；Revision 还持久化 exact RFC 8785 canonical Profile manifest/manifest SHA 与 Provider schema/schema SHA。PostgreSQL deferred closure 从 exact Source/Revision/ordered child rows重算 authority digest、包含两项 raw content SHA 的 `asset-source-definition.v2` digest 和固定 20-frame binding digest。Direct SQL 提供的摘要只是待比对值，不能成为可信事实；任一成员、manifest/schema byte、顺序、字段或摘要漂移整笔回滚。
- Source enum 只表示领域分类，不表示 Provider 已安装或可用。`PublishedBindingEligible` 只校验已加载 Source/Revision 行闭包；生产 admission 必须重新加载 exact Scope、已安装 Profile/Adapter 以及所需 Connection/Runtime/Capability 事实。
- `000015` 通过 `asset_catalog_future_source_gate_admitted(asset_sources) IS NOT TRUE` 的默认拒绝同时阻止 K8S/AWX 初始 Source commit 与 `VALIDATING|AVAILABLE|DEGRADED`；false/NULL 都 fail closed，而已有 Source 向 `UNAVAILABLE|SUSPENDED` 收敛始终不依赖 hook。`000017`/`000019` 只替换该同签名 body，分别加入自己 SourceKind 的 same-transaction initial creation closure、进入 VALIDATING 前的 exact typed binding/runtime；AVAILABLE/DEGRADED 除已发布成功 proof/cleanup 外还必须重载 Task 19A2b current unexpired gate-evidence pointer/digest（shape 由 19A2a 冻结）与 Provider-owned qualification/HA/canary closure。它们各自承担 down guard、恢复与 schema-admission 证据，不复制 Phase 1 Source trigger。
- Source Gate qualification 逐字消费规范 [§5.2.1](../../../specs/2026-07-13-operational-assets-controlled-access-design.md#521-source-gate-qualification-唯一持久-abi)：`asset_sources` exactly 3 nullable pointer columns；`asset_source_runs` exactly 13 qualification + 10 HA nullable columns；所有 digest 是 lowercase 64-hex，signature 是 canonical unpadded base64url，receipt issued time 不得复用 pre-cleanup `work_result_recorded_at`。
- qualification-required Profile 的 `AVAILABLE|DEGRADED` 必须持有 all-present pointer，其余 gate 状态必须 all-null；唯一 durable 判别为 exact `MANUAL/MANUAL_V1/MANUAL_V1` 返回 false、exact non-MANUAL 且 provider/profile 均非 `MANUAL_V1` 返回 true，mixed/missing 返回 unknown 并按 `IS TRUE` fail closed。identity 只有 named four-column deferred FK `(tenant_id,workspace_id,id,gate_evidence_run_id) → (tenant_id,workspace_id,source_id,id)`，digest/expiry 只是 payload。named deferred trigger 必须在 commit 复验 exact Scope/Source/revision/binding、terminal canary、`REVOKED` cleanup、15-frame structural receipt、prior HA 与 zero projection。`source.gate_revision=qualification_run.gate_revision+1` 只约束 `AdmitGate` 首次写 pointer；后续同 binding rollover 的 `DEGRADED|AVAILABLE` 保留 current unexpired pointer，并以从 admission epoch 到当前 epoch 的无间隙 terminal rollover receipt chain 闭合，`SUSPENDED` 同事务清 pointer。partial/cross-Scope/wrong-kind/nonterminal/expired/mismatch/错误 binding/revision/缺 HA、epoch 跳跃或 receipt-chain 缺口必须 commit fail；关闭、漂移或过期原子清 pointer。
- `000015` 只新增 canonical `public.asset_catalog_seal_qualification_receipt(uuid,uuid,uuid,uuid,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text)` 与 `public.asset_catalog_admit_source_gate(uuid,uuid,uuid,uuid,bigint,bigint)` 两条 `SECURITY DEFINER` primitive；ordinary runtime/workload均无 EXECUTE，独立 sealer only seal、admitter only admit且无 relation/sequence ACL。两者固定 target Run→receipt/UUID-ordered prior Runs→Source→Revision锁序与 exact CAS；first-write seal在 durable `REVOKED` 后只接受同一 transaction的 DB issued time、cleanup-time ordering与 `expiry<=issued+24h`，再派生 receipt/HA/terminal/Audit；已封存 exact tuple只读 replay，changed replay拒绝。admit派生 pointer/open Audit/Outbox。A2a只做 structural closure；current Profile/runtime/signing-key与密码学验签由A2b/A2c immutable registry/evaluator完成。Source三列 direct INSERT/UPDATE、Run23列 direct UPDATE与非 queue-binding16列 direct INSERT必须`42501`。migration-owner disposable fixture/synthetic signature只证明 structure，不计验签、A2a/A2b/G2/G4/availability。
- Routine ACL 双层固定为`000015` owned exact38与application schema global exact110=predecessor72+Asset38。唯一C-order identity list与production digest见 [Pack06 canonical predecessor exact72 runtime EXECUTE manifest](./06-source-external-cmdb.md#canonical-predecessor-exact72-runtime-execute-manifest)；本README不复制列表。基线direct grant0、normalized PUBLIC72；migration/admission/test必须逐项匹配该列表并使用该production常量，不得运行时生成后接受。up显式revoke PUBLIC72/owned38并grant runtime exact72 owner-grantor/non-grantable edges；up后PUBLIC0、runtime direct/effective90、workload direct0/effective90，capability edge仍仅seal/admit。down先revoke新增runtime72，再删除owned38并恢复PUBLIC72，最终catalog/ACL等于pre-up；禁止schema-wide grant/revoke或恢复未知对象。未来`000016..000022`新增/替换public routine必须更新global manifest、显式revoke与rollback contract，否则admission关闭。
- `REJECTED` revision 的 canonical content 仍不可变；允许以新的 append-only Validation Run 执行 `REJECTED → VALIDATING`，但禁止直接 `REJECTED → PUBLISHED`。
- `assets_kind_check` 在 `000015` 固定 Phase 1 的 17 个 Kind，Phase 3 只能通过 `000017` 显式替换该命名约束后扩展 Victoria taxonomy。
- ProviderKind 使用大写 profile token `^[A-Z][A-Z0-9_]{0,63}$`；UUID 使用小写 RFC 4122 version 1–5/RFC variant；labels 最多 64 对且 UTF-8 序列化不超过 16 KiB；Idempotency-Key 复用 `domain.ValidIdempotencyKey` 的最多 128 字节小写 grammar。
- Relationship 显式保存 source/target Environment 与 Asset、Provenance、可空 provenance source/cross-environment policy、状态、版本和时间；不得虚构 Schema 中不存在的 confidence/last-observed 字段。
- Binding 状态只有 `ACTIVE/INACTIVE`。`CreateBinding`、`DeleteBinding` 与 Conflict decision 都返回持久 `MutationReceipt`；HTTP 204 仍从 receipt 生成 Audit/Replay headers。
- `service_asset_bindings` 同时由数据库 FK 与 Repository 验证 legacy `service_bindings(service_id,environment_id)` 资格；只验证同 Workspace 不足以创建 Binding。
- M1F 在同一 `SERIALIZABLE READ WRITE` transaction 内先完成 Conflict/Asset 固定锁序，再调用 runtime-only `public.asset_catalog_lock_exact_service_binding(uuid,uuid,uuid,uuid)`；函数以 `SECURITY DEFINER` 依次锁 exact Service `FOR KEY SHARE` 和 exact legacy binding `FOR SHARE` 并要求 `EXACT`。Workload/runtime 对 `services`/`service_bindings` 无 UPDATE/grant option，直接 row lock 必须 `42501`。
- Limiter 按 `SOURCE→WORKSPACE→PROVIDER` 锁定三张 `asset_source_limit_buckets` row，通过 `next_token_at+version+last_receipt_id` CAS 提交；active permit 与 Release/Delay/Expiry 的唯一事实是 `asset_source_limit_permits` 的 ACQUIRE/terminal append-only ledger。相同 request/command digest 的响应丢失只回放原 receipt，changed digest、第二 terminal receipt、跨 Run/Provider/bucket 或过期状态均 fail closed；Source backpressure、Queue fence 与 advisory/process memory 都不是 Limiter truth。
- Task 2 唯一拥有 SourceScope、安全 SourceRun、Relationship/Conflict 与资产/映射基础契约；Pack 02/03 直接消费，不复制 DTO。Source mutation、Profile Registry 与 sealed typed-extension session 仅由 Pack 05 Task 13 拥有，且永不暴露 SQL/pgx/raw transaction。
- `IsLifecycleEdge` 只表达无 self-edge 的结构图，不代表授权；幂等 replay 先读 receipt，公开 transition 仍由管理层按当前可信事实收窄。任何写命令中的 Tenant/route Scope、actor/auth time、Trace、Idempotency-Key、request hash 与 CAS 都由 verified Principal、完整 path/header 和服务端 canonicalization 注入，不能来自 JSON DTO。

## 来源实施与门禁状态表

| Source/Profile | Phase 1 实施归属 | 生产开门证据 |
|---|---|---|
| `MANUAL` | 已有受治理 Asset API；不进 Worker | OIDC/Scope/ETag/Idempotency/Audit；不代表外部资源接管 |
| `CSV_IMPORT/CSV_RFC4180_V1` | Pack 05 | 签名、stream/DLP、checkpoint、tombstone/recovery、HA/cleanup |
| `CONTROL_PLANE_API/API_BATCH_V1` | Pack 05 | mTLS workload identity、JWS、sequence/checkpoint、rate/fence |
| `EXTERNAL_CMDB/CMDB_CATALOG_V1` | Pack 06 | identity/TLS/read-only protocol、incremental/provenance、staging canary |
| `VSPHERE/VSPHERE_VCENTER_V1` | Pack 07 | Task 21A same-attempt full；另需 21B0 resident authority、21B cross-Run delta/leave/HA、vCenter UUID/TLS/privilege与 lab canary；缺任一项 `UNAVAILABLE` |
| `PROXMOX/PROXMOX_VE_V1` | Pack 08 | cluster identity/read-only HTTPS、snapshot digest、lab canary |
| `OPENSTACK/OPENSTACK_NOVA_V2_1` | Pack 08 | Keystone project/region、Nova paging/delete、lab canary |
| `CLOUD_PROVIDER/AWS_EC2_V1` | Pack 08 | STS account/role、EC2 paging/quota、sandbox canary |
| `CLOUD_PROVIDER/AZURE_COMPUTE_V1` | Pack 08 | tenant/subscription/workload identity、pager/quota、sandbox canary |
| `CLOUD_PROVIDER/GCP_COMPUTE_V1` | Pack 08 | project/workload pool、aggregated paging/quota、sandbox canary |
| `KUBERNETES_OPERATOR` | **Phase 3 提供** | Phase 1 显式 `UNAVAILABLE`，不用通用 K8s/HTTP 替代 |
| `AWX_INVENTORY` | **Phase 5 提供** | Phase 1 显式 `UNAVAILABLE`，不用通用 HTTP 替代 |

任一行的 `AVAILABLE` 都只对 exact source/profile/revision/binding 生效，不打开同家族、同 Workspace 或同网络的其他来源。

## Exit Gate

Phase 1 只有在以下全部成立时才可记录 `ASSET_CONTROL_PLANE_ACCEPTED`：

- 11 个任务包的 checkbox 和 commit 边界全部完成；不得先标记状态再补 Provider。
- PostgreSQL 18.4 的十二表迁移、跨 Scope FK、Source Revision/authority membership 不可变与唯一发布、Limiter 三 bucket/permit receipt、runtime-only M1F parent lock、checkpoint/fence、并发/幂等、Outbox/Audit、备份恢复和应用回滚通过。
- Source 六步向导、`ASSET_SOURCE_*` 权限、OpenAPI 严格 Schema、ETag/Idempotency/reauth、`effective_actions` 与唯一生成类型通过。
- Browser Config 无 Secret/私有 Endpoint 且 malformed fail closed；浏览器/API OIDC `iss/aud/azp/auth_time` 分别验证，生产不依赖 `VITE_OIDC_*` 注入身份配置。
- CSV/API/CMDB/vSphere/Proxmox/OpenStack/AWS/Azure/GCP 均有真实 protocol serialization、negative/DLP/provenance、incremental checkpoint、soft delete/recovery、rate/backpressure、credential cleanup、两副本 HA/fence 与非生产 canary 签名证据。
- `cmd/discovery-worker` 生产构造器仅使用真实 PostgreSQL、workload identity、secure profile/session transport、checkpoint keyring 和 Provider registry；Broker `SessionOpener` 与 runtime resolver 只能来自同一 Task 28B attempt authority。Task 28B 只拥有 fixed-mTLS client/本地 composition，不拥有 shared authority server。Worker A 被 kill 后，replacement Worker 必须通过 opaque lab binding 连接已预置真实外部 authority，以 exact Run/attempt/epoch recovery-open 同一 attempt session 再 revoke；新 process-local Broker 直接按 UUID revoke不算证据，缺 binding/不可达/mTLS 失败或任一依赖缺失均 fail closed。该 cleanup proof不能恢复 vSphere collector/filter/version，也不能满足 Task 21B0。
- External CMDB Task 18B G2 必须使用 PostgreSQL 18.4 TLS 与 `AIOPS_TEST_POSTGRES_DSN`，缺环境或 Skip 不得算 PASS；partial/timeout、same-attempt runtime/handle/proof、stale fence、one-transaction page/relation/checkpoint/receipt、replay、complete-only missing、fixed-wire tombstone/restore、crash/reclaim 与 cleanup-before-Delay 全部通过。两 Worker/HA/restart/recovery 未完成 G3 前旧 Task 18 不得勾选。
- vSphere Task 21A G2 只证明同一 live claim/session/collector 的 bounded `RetrievePropertiesEx → ContinueRetrievePropertiesEx` 和 complete-only closure；raw token只在 `BoundRuntime`，session/token loss保持旧 checkpoint和 `missing=0`。vSphere→PageCommitter/PostgreSQL 关闭态证据唯一落在 `internal/assetcatalog/postgres/vsphere_discovery_integration_test.go`：Task 21A 创建、Task 21B 顺序修改，绝不成为通用 Worker/其他 Provider/shared helper owner。Task 21B0 必须另以真实 TLS resident authority + govmomi simulator + PostgreSQL 18.4 证明跨 Run fence/owner handoff、credential rotation、terminal revoke/no-orphan，以及同一 resident session/collector 的 `filter + initial version + full pages + delta drain + non-truncated closure` 无间隙 bootstrap；Task 21A 独立 checkpoint不能成为 incremental cursor。Task 21B 再证明 `WaitForUpdatesEx` enter/modify/leave、soft-delete、collector expiry rollover与 HA resume。三者未全部完成时 Task 22、Task 28C vSphere row、vSphere HA/canary/matrix均关闭。
- Task 19A 必须从 Task 18B neutral `internal/sourceprofile` descriptor 与 Task 28C safe runtime-admission manifest 装配 Control Plane registry/admission，并把需真实资格的 non-MANUAL publication 固定为 `PUBLISHED + UNAVAILABLE`；`cmd/control-plane` 不得 import External CMDB Provider、Provider HTTP-client、credential/session/network graph，也不得读取 endpoint、credential 或 runtime material；其既有 HTTP server graph 不受影响。缺 descriptor/runtime/gate prerequisite 时公共 validation path 零写并保持关闭。
- 当前唯一顺序为 `reachability docs corrective → manager exact-3 contract sync → source-gate capability-identity harness C0 → pre-A2a exact-2 routine/test-boundary corrective → manager exact-3 evidence sync → global routine ACL exact-11 contract + status sync → pre-A2a formal-fixture compatibility exact-9 corrective → pre-A2a identity-FK fixture compatibility exact-9B docs-only contract checkpoint → [DEVELOPMENT_PAUSED] → resumed fresh test-only identity-FK fixture corrective → fresh Task 19A2a exact-12 → post-A2a exact-2 validation corrective → Task 19A2b → Task 19A2c → Task 29A → Task 19B → Task 29B`。PR #152 exact11与PR #153 exact9已合并；截至2026-07-23 exact9B只冻结docs-only合同，原Phase B test-only实现`NOT_STARTED`且不是本交付。全部partial A2a均为`STOPPED/NOT PASS`，停止的`cb00`与其他旧dirty/stopped A2a worktree/WIP/snapshot不得读取、续用或复制，任何未完成实现不提交、不合并。恢复后须从届时最新`origin/main`新建fresh独立test-only identity-FK fixture corrective，以唯一named exact four-column identity FK两种合法表达完成严格识别/可逆剥离、完整负例、验证、复核、PR/merge，并保持PR #153 auxiliary及全部negative/global/owned/ACL/down合同；之后才可fresh A2a。docs-only exact9B不实现migration/A2a/G2、不改完成度或能力；A2a exact12不得修改该helper。A2a合并后 post-A2a exact-2仍只拥有`internal/assetcatalog/validation.go`与新建`internal/assetcatalog/validation_test.go`；A2b/A2c文件零重叠且只有A2c可复用Task28A唯一loop。Qualification不得进入browser`effective_actions`、普通`RequestSync`、PageCommitter或Source checkpoint/success projection；所有Source/Provider/Worker保持`NOT_STARTED/UNAVAILABLE/CLOSED`。
- `/overview` 和资产/映射/来源页在 1440/1024/390、键盘、axe、真实 Keycloak/PostgreSQL E2E 通过；未实现后续能力显示 `NOT_STARTED/UNAVAILABLE`，无伪绿。
- 前端静态门证明 `app → features → shared`、仅 `shared/api` 网络访问、generated contract 无漂移、Scope 切换清理 Query；治理 mutation 不 optimistic/自动重试，公共治理组件由各 feature 复用。
- 生产 Web E2E 从 Go 同源入口加载；`/api/*`/health/readiness 不被 SPA fallback，最终 Control Plane 产物从 `/opt/aiops/web` 服务且无 Node/Vite/MSW/source map/独立 BFF 运行时。
- `docs/design/frontend/foundation-assets.md`、`asset-sources.md`、`overview.md` 、V4、ADR、Runbook、OpenAPI、status 和 AGENTS 已持久化、链接可达且无平行事实源。
- secret/DLP、生成类型漂移、代码围栏、本地链接、不完整标记、`git diff --check`、Go/race/vet/build、Web/E2E 和恢复门全部通过。

已实现 Provider 软件不等于某个生产 Source 已开门；没有 exact 当前证据的 source 仍保持 `UNAVAILABLE/SUSPENDED`。Phase 1 验收也不等于整个项目生产闭环；只有 Phase 8 独立签名的 `PRODUCTION_CLOSED_LOOP_ACCEPTED` 才可这样描述。

本次八文档 C0 reachability docs corrective 只冻结上述 mutation authority、structural/current trust 边界与串行顺序，不修改 `docs/status/current.md`、migration、Go/Web/OpenAPI 或 checkbox，不执行 A2a/A2b/G2/G4。它不能把任何 fixture、旧 dirty worktree或未合并实现变成事实源；所有 Provider/Worker 继续 `UNAVAILABLE/CLOSED`，资格证据继续 deferred。

本次八文件 C0 Source Gate qualification DAG 纠偏只更新规范与计划，不拥有 `docs/status/current.md`，也不据此勾选任何实现 checkbox。PR #97 已在本纠偏前单独合并，只负责同步 Task 18A/PR #99 等完成度事实；其中把 Task 18B 后续证据宽泛列为 PostgreSQL/Worker/HA 的文字不得继续解释为文件或通用状态机 owner。本契约合并后，主管理/状态窗口再单独同步该措辞，不能由本 PR 改写 `current.md`；所有 Provider row 与 production Worker availability 仍为 `UNAVAILABLE/CLOSED`，G3/G4 继续 deferred，具体实现完成度只由 `current.md` 记录。

本次三文件 vSphere session-continuity C0 纠偏同样只修改 Pack 07、Pack 09 与本 README，不修改 `docs/status/current.md`，也不把 Task 21A/21B0/21B 写成已实现。它只消除“sealed checkpoint 或 Task 28B 可恢复 PropertyCollector session”的假入口；vSphere 全程 `UNAVAILABLE/CLOSED`，真实 authority、incremental/HA、G3/G4、gate/canary/matrix继续 deferred。

## 唯一前端扩展契约

| 责任 | 唯一文件/规则 |
|---|---|
| Router / Navigation | `web/src/app/router.tsx` / `web/src/app/navigation.ts` |
| Scope | `workspace`、`environment` 位于 validated URL search；刷新/后退/分享恢复相同安全投影 |
| 模块边界 | `app → features → shared`；feature 不直接导入其他 feature UI，跨域只传 typed route/稳定 ID；ESLint 强制 |
| 状态所有权 | URL=Scope/筛选/排序/Cursor/Tab/selection/Operation ID；TanStack Query=Scope-keyed server state；RHF+Zod=form；local React=短期 UI；无 Redux/Zustand |
| Assets | `web/src/features/assets/AssetCatalogPage.tsx`、`AssetDetailPage.tsx` |
| Sources | `web/src/features/asset-sources/`；修订向导与 run timeline 不另建工程 |
| Overview | `web/src/features/overview/OverviewPage.tsx` |
| Browser config/auth | 启动先读取 `/api/v1/browser-config`，再由 `web/src/app/auth/keycloak.ts` 初始化；Token 仅内存，high-risk 使用 `reauthenticate(returnURL)` |
| API | `control-plane-v1.yaml` → `schema.d.ts`；低层 transport 私有且仅 `shared/api` 可访问网络，禁止字符串泛型 path/direct fetch/手写 DTO |
| Shared operation/UI | Phase 1 建立共享 Operation query/polling 和 `DataTable`、`ProblemPanel`、`OperationTimeline`、`EffectiveActionGate`、`ETagConflictReview`、`ReauthBoundary`；后续只扩展 |
| Mutation | 服务端确认；无 optimistic update、自动重试或副作用重放；统一 Idempotency-Key、ETag/If-Match、reauth、durable Operation |
| 生产服务 | Vite 仅开发/构建；Go 从 `/opt/aiops/web` 同源服务 SPA/API，静态缺失 readiness fail closed；无独立 Node/Web/BFF |
| 持久设计 | `foundation-assets.md`、`asset-sources.md`、`overview.md` |

后续阶段不得重新定义 220px 导航、46px Scope bar、4–6px 圆角、Phase 1 semantic tokens、OIDC 生命周期、URL/Query 状态语义、API transport 或 Operation/UI primitives，也不得建立聊天/终端/AI 隐喻的平行 UI。智能体验只通过 Investigation、Evidence、ActionProposal、ActionPlan、Operation、Receipt 和 Audit 呈现。

## 工作区注意

当前主工作区包含 `.worktrees/*`，全仓 AST 唯一性测试会扫描这些副本。实施和验收必须在仓库树之外的隔离 worktree；不得删除用户 worktree，也不得声称当前主工作区 `go test ./...` 已全绿。
