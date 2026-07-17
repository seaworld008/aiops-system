# 01 — 资产目录、真实发现来源与 Control Plane

本目录把 Phase 1 拆成 11 个生产任务包。它是[受治理运维能力总计划](../../2026-07-13-governed-operations-program.md)的第一阶段，产品、安全和前端语义以[已确认设计规范](../../../specs/2026-07-13-operational-assets-controlled-access-design.md)为准；快速构建的 Batch、并发和验证时机由[快速开发与真实验收计划](../../2026-07-15-fast-development-validation-program.md)统一覆盖。

本阶段的终点不是枚举、假 Provider、静态页面或 Demo：它建立十二表 PostgreSQL 事实（含不可变 Source Revision 权限 Environment 子表，以及独立 Limiter bucket 与 permit/receipt truth）、不可变 Source Revision、真实 CSV/API/CMDB/vSphere/Proxmox/OpenStack/AWS/Azure/GCP 协议适配、独立 Discovery Worker、HA lease/fence、加密 checkpoint、持久背压、逐 Provider gate，以及真实 OIDC/OpenAPI、Go 同源 SPA、类型化应用平台和 Overview。它仍不开放目标系统写操作；项目最终通过 Phase 7/8 的不可变 ActionPlan、策略、重新认证、人工审批、短凭据、类型化执行、独立验证、对账/回滚/升级与审计形成生产闭环。

## 产品依赖与最终验收顺序

1. [01-schema-domain.md](./01-schema-domain.md) — 创建 `000015_assets_catalog` 十二张表、Source Revision 权限 Environment/Run/Fence/Checkpoint、Limiter bucket/permit receipt 约束与稳定领域接口。
2. [02-repository-discovery.md](./02-repository-discovery.md) — 实现 Scope Repository、append-only Observation、provenance、tombstone/恢复和原子 checkpoint 投影。
3. [03-mapping-auth-api.md](./03-mapping-auth-api.md) — 实现关系/冲突/Service Binding、Browser/API OIDC 边界、runtime Browser Config、OpenAPI/HTTP 基线和真实 Control Plane 装配。
4. [04-web-foundation-assets.md](./04-web-foundation-assets.md) — 建立唯一 `web/`、`app → features → shared`、真实浏览器 OIDC、typed API/shared Operation/治理 UI、Go SPA、资产/映射/来源基线和持久前端 Foundation 规范。
5. [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md) — 实现 Source `draft→canonical revision→validate→publish/disable→sync`、权限/OpenAPI/effective_actions、CSV 与 mTLS API ingestion、六步 Source 向导。
6. [06-source-external-cmdb.md](./06-source-external-cmdb.md) — 实现固定 External CMDB Catalog v1 协议；Task 18A 只拥有 Provider paging/checkpoint，Task 18B 在 Pack 09 provider-neutral Worker core 合并后只拥有 CMDB durable reconciliation/lifecycle integration 和唯一 neutral metadata descriptor，Task 19A 单独装配 Control Plane profile/validation admission并把 non-MANUAL publication 保持关闭，Task 19A2a/19A2b/19A2c 再依次建立 qualification schema/domain/admission、persistence/runtime rechecks、复用 Task 28A Worker seam 的私有 API/production，Task 19B 才拥有 CMDB canary/evaluator/AdmitGate operating proof。
7. [07-source-vsphere.md](./07-source-vsphere.md) — 实现 govmomi SOAP/PropertyCollector 全量+增量库存、删除/恢复、非生产 vCenter canary 和 gate。
8. [08-source-proxmox-openstack-cloud.md](./08-source-proxmox-openstack-cloud.md) — 实现 Proxmox、OpenStack、AWS、Azure、GCP 五个独立计算资产 Provider/gate。
9. [09-discovery-worker-ha-e2e.md](./09-discovery-worker-ha-e2e.md) — Task 27 只冻结自身已合并的 PostgreSQL Queue/process-local CleanupBroker/Limiter，M1E 继续唯一拥有既有 PageCommitter ABI/SQL；Task 28A 先交付 provider-neutral Worker core/claim-runtime seam，Task 28B 再交付 recoverable cleanup-session transport/same-attempt authority，Task 28C 才拥有 registry/production constructor/`cmd/discovery-worker`，Task 29A 只产 two-worker HA/cleanup/restart/response-loss receipt 与低基数 metrics，Task 29B 最后聚合已完成 per-source gate/canary/HA receipts。
10. [10-overview-control-room.md](./10-overview-control-room.md) — 闭合 `/overview` 安全聚合 API/UI，分维显示 Assets/Sources/Connections/Investigations/Actions/Releases，未实现项显式 `NOT_STARTED/UNAVAILABLE`。
11. [11-e2e-docs.md](./11-e2e-docs.md) — 完成指标、真实 Keycloak/PostgreSQL/Playwright、视觉/axe/安全、CI、备份恢复、HA、持久文档和 Phase 1 签名验收。

快速构建桥接任务包 [12-m1e0-relation-page-corrective.md](./12-m1e0-relation-page-corrective.md) 已由 PR #46 关闭 fixed canonical empty relation digest 与 `000015` trigger 的 C0 冲突；[14-m1c1-normalized-fact-contract-corrective.md](./14-m1c1-normalized-fact-contract-corrective.md) 已由 PR #49 关闭 normalized fact/Asset/SQL parity 与 page-byte accounting；[13-m1e-page-commit-transaction.md](./13-m1e-page-commit-transaction.md)、Queue lifecycle、CleanupBroker 与 Limiter runtime 已由 PR #53/#55/#57/#64 分别合并并保持运行能力关闭。External CMDB Task 18A paging/checkpoint 已由 PR #98 合并并由 PR #99 修正 complete-checkpoint next-run restart；这仍不是 Task 18 durable lifecycle、Worker 或 gate 完成证据。

Task 18B 与 Task 27/28 的权威顺序现固定为：已合并 PageCommitter/Queue/process-local CleanupBroker/Limiter → [Task 28A provider-neutral Worker core](./09-discovery-worker-ha-e2e.md#task-28a-provider-neutral-worker-core-and-claim-runtime-seam) → [External CMDB Task 18B](./06-source-external-cmdb.md#task-18b-external-cmdb-durable-reconciliation-and-lifecycle-integration) provider-specific 真库集成 + neutral descriptor → [Task 28B recoverable session transport](./09-discovery-worker-ha-e2e.md#task-28b-recoverable-cleanup-session-transport-and-attempt-authority) → [Task 28C production](./09-discovery-worker-ha-e2e.md#task-28c-production-constructor-and-provider-registry)。Source Gate qualification DAG 再严格固定为 [Task 28C](./09-discovery-worker-ha-e2e.md#task-28c-production-constructor-and-provider-registry) → [Task 19A](./06-source-external-cmdb.md#task-19a-control-plane-cmdb-profile-installation-and-validation-admission) → [Task 19A2a](./06-source-external-cmdb.md#task-19a2a-source-gate-schema-domain-and-admission-contract) → [Task 19A2b](./06-source-external-cmdb.md#task-19a2b-source-gate-persistence-and-runtime-admission-rechecks) → [Task 19A2c](./06-source-external-cmdb.md#task-19a2c-qualification-lane-api-and-production-assembly) → [Task 29A](./09-discovery-worker-ha-e2e.md#task-29a-provider-neutral-two-worker-ha-receipt-and-telemetry) → [Task 19B](./06-source-external-cmdb.md#task-19b-per-source-availability-gate-real-staging-canary-and-operating-proof) → [Task 29B](./09-discovery-worker-ha-e2e.md#task-29b-signed-provider-matrix-and-final-e2e-ci)。19A2a/19A2b/19A2c 分别 12/11/19 files，由新窗口独立真实 G2/PR/merge且两两零重叠；19A2c 必须复用 `worker.go/worker_test.go/claim_runtime.go/claim_runtime_test.go` 的唯一 Task 28A loop，seam 不足时先停并做四文件 sequential C0 corrective，禁止第二 runner。Task 29A 只用 19A2b durable facts、19A2c sole signer 与 Task 28C production observer seam；seam 不足时先停做冻结六文件 corrective。任何后继只读已合并接口，不读取其他会话未提交实现。

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
- `SourceRevisionRepository`、`discoverysource.Provider`、已合并 `discoveryqueue.Queue`；Task 28A 唯一产生 provider-neutral `discoveryworker.Worker`/claim-runtime seam，Task 28B 唯一产生 fixed-mTLS recoverable session transport/same-attempt authority，Task 28C 唯一产生 exact Provider registry、production constructor、observer/decorator seam 与真实 `cmd/discovery-worker`；Task 19A2a/19A2b/19A2c 依次唯一产生 qualification schema/domain/admission、persistence/runtime rechecks、复用唯一 Worker loop 的 fixed workload API + immutable verifier registry/sole sink+signer，Task 29A/各 Provider gate/Task 29B 依次只产 HA receipt+real-binary metrics、per-source canary+decision、final matrix。
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

`Source Revision` 内容在创建后不可修改；成功路径固定为 `DRAFT → VALIDATING → VALIDATED → PUBLISHED → SUPERSEDED`，失败路径为 `VALIDATING → REJECTED`，同一不可变内容可通过新的 Validation Run 重新进入 `VALIDATING`，但 `REJECTED` 不能直接发布。除 `MANUAL_V1` 外，publication 固定落在 `PUBLISHED + UNAVAILABLE`；fixed workload-only qualification 只能产生零 Catalog projection 的 signed safe receipt，最终由唯一 serializable `AdmitGate` 进入 `AVAILABLE`。普通 `RequestSync`/data claim 在此之前仍拒绝。Source 可用需 exact `ACTIVE + PUBLISHED + AVAILABLE`；Asset 进入运行还需 `EXACT + ACTIVE`。来源 gate、Asset lifecycle、Connection publication 和 Capability availability 不得相互代替。

## 阶段内稳定数据契约

- Source/Asset revision 在 PostgreSQL、Go、OpenAPI 和生成 TypeScript 中统一为 `int64`。`Asset.LastSourceRevision` 对应 `assets.last_source_revision`。
- `SourceRevision.BindingDigest() == CanonicalRevisionDigest`。`.v1` 固定 20 个 `FramedTupleV1` 帧：domain、Tenant/Workspace/Source/Revision、Provider/Profile definition digest、Integration、sync、三个 Opaque Reference、authority digest、四个 rate/backpressure 整数、Profile、schedule、typed-extension code/digest；无 extension 时最后两帧也必须为 `NULL`。`source_definition_digest` 不能吸收或替代 extension/binding digest，所有 SHA-256 以 32 raw bytes 入帧。
- `asset_source_revision_authorities` 是 1–100 个 same-Scope Environment membership 的唯一事实源；Revision 还持久化 exact RFC 8785 canonical Profile manifest/manifest SHA 与 Provider schema/schema SHA。PostgreSQL deferred closure 从 exact Source/Revision/ordered child rows重算 authority digest、包含两项 raw content SHA 的 `asset-source-definition.v2` digest 和固定 20-frame binding digest。Direct SQL 提供的摘要只是待比对值，不能成为可信事实；任一成员、manifest/schema byte、顺序、字段或摘要漂移整笔回滚。
- Source enum 只表示领域分类，不表示 Provider 已安装或可用。`PublishedBindingEligible` 只校验已加载 Source/Revision 行闭包；生产 admission 必须重新加载 exact Scope、已安装 Profile/Adapter 以及所需 Connection/Runtime/Capability 事实。
- `000015` 通过 `asset_catalog_future_source_gate_admitted(asset_sources) IS NOT TRUE` 的默认拒绝同时阻止 K8S/AWX 初始 Source commit 与 `VALIDATING|AVAILABLE|DEGRADED`；false/NULL 都 fail closed，而已有 Source 向 `UNAVAILABLE|SUSPENDED` 收敛始终不依赖 hook。`000017`/`000019` 只替换该同签名 body，分别加入自己 SourceKind 的 same-transaction initial creation closure、进入 VALIDATING 前的 exact typed binding/runtime；AVAILABLE/DEGRADED 除已发布成功 proof/cleanup 外还必须重载 Task 19A2b current unexpired gate-evidence pointer/digest（shape 由 19A2a 冻结）与 Provider-owned qualification/HA/canary closure。它们各自承担 down guard、恢复与 schema-admission 证据，不复制 Phase 1 Source trigger。
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
| `VSPHERE/VSPHERE_VCENTER_V1` | Pack 07 | vCenter UUID/TLS/privilege、SOAP full+delta、lab canary |
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
- `cmd/discovery-worker` 生产构造器仅使用真实 PostgreSQL、workload identity、secure profile/session transport、checkpoint keyring 和 Provider registry；Broker `SessionOpener` 与 runtime resolver 只能来自同一 Task 28B attempt authority。Task 28B 只拥有 fixed-mTLS client/本地 composition，不拥有 shared authority server。Worker A 被 kill 后，replacement Worker 必须通过 opaque lab binding 连接已预置真实外部 authority，以 exact Run/attempt/epoch recovery-open 同一 session 再 revoke；新 process-local Broker 直接按 UUID revoke不算证据，缺 binding/不可达/mTLS 失败或任一依赖缺失均 fail closed。
- External CMDB Task 18B G2 必须使用 PostgreSQL 18.4 TLS 与 `AIOPS_TEST_POSTGRES_DSN`，缺环境或 Skip 不得算 PASS；partial/timeout、same-attempt runtime/handle/proof、stale fence、one-transaction page/relation/checkpoint/receipt、replay、complete-only missing、fixed-wire tombstone/restore、crash/reclaim 与 cleanup-before-Delay 全部通过。两 Worker/HA/restart/recovery 未完成 G3 前旧 Task 18 不得勾选。
- Task 19A 必须从 Task 18B neutral `internal/sourceprofile` descriptor 与 Task 28C safe runtime-admission manifest 装配 Control Plane registry/admission，并把需真实资格的 non-MANUAL publication 固定为 `PUBLISHED + UNAVAILABLE`；`cmd/control-plane` 不得 import External CMDB Provider、Provider HTTP-client、credential/session/network graph，也不得读取 endpoint、credential 或 runtime material；其既有 HTTP server graph 不受影响。缺 descriptor/runtime/gate prerequisite 时公共 validation path 零写并保持关闭。
- Task 19A2a/19A2b/19A2c 必须分别以独立 PR在既有十二表上提供 safe evidence/HA digest schema + pure contracts、expiry/CAS/drift/HA receipt persistence + serializable `AdmitGate`、fixed mTLS qualification API + immutable verifier registry/sole sink+signer；三批 files 零重叠且只有 19A2c 可复用 Task 28A 唯一 loop，不得创建独立 qualification runner。Qualification 不得进入 browser `effective_actions`、普通 `RequestSync`、PageCommitter 或 Source checkpoint/success projection。Task 29A `ha.go` 只验证 19A2b Repository-loaded facts并经 19A2c signer封存，metrics 只经 Task 28C production decorators接真实 binary；Task 19B 才产生 External CMDB canary/evaluator并调用 `AdmitGate`；Task 29B 只聚合已完成 receipts，不重建三者。
- `/overview` 和资产/映射/来源页在 1440/1024/390、键盘、axe、真实 Keycloak/PostgreSQL E2E 通过；未实现后续能力显示 `NOT_STARTED/UNAVAILABLE`，无伪绿。
- 前端静态门证明 `app → features → shared`、仅 `shared/api` 网络访问、generated contract 无漂移、Scope 切换清理 Query；治理 mutation 不 optimistic/自动重试，公共治理组件由各 feature 复用。
- 生产 Web E2E 从 Go 同源入口加载；`/api/*`/health/readiness 不被 SPA fallback，最终 Control Plane 产物从 `/opt/aiops/web` 服务且无 Node/Vite/MSW/source map/独立 BFF 运行时。
- `docs/design/frontend/foundation-assets.md`、`asset-sources.md`、`overview.md` 、V4、ADR、Runbook、OpenAPI、status 和 AGENTS 已持久化、链接可达且无平行事实源。
- secret/DLP、生成类型漂移、代码围栏、本地链接、不完整标记、`git diff --check`、Go/race/vet/build、Web/E2E 和恢复门全部通过。

已实现 Provider 软件不等于某个生产 Source 已开门；没有 exact 当前证据的 source 仍保持 `UNAVAILABLE/SUSPENDED`。Phase 1 验收也不等于整个项目生产闭环；只有 Phase 8 独立签名的 `PRODUCTION_CLOSED_LOOP_ACCEPTED` 才可这样描述。

本次八文件 C0 Source Gate qualification DAG 纠偏只更新规范与计划，不拥有 `docs/status/current.md`，也不据此勾选任何实现 checkbox。PR #97 已在本纠偏前单独合并，只负责同步 Task 18A/PR #99 等完成度事实；其中把 Task 18B 后续证据宽泛列为 PostgreSQL/Worker/HA 的文字不得继续解释为文件或通用状态机 owner。本契约合并后，主管理/状态窗口再单独同步该措辞，不能由本 PR 改写 `current.md`；所有 Provider/Worker 仍为 `NOT_STARTED/UNAVAILABLE/CLOSED`，G3/G4 继续 deferred。

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
