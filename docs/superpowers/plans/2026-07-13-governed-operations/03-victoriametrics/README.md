# VictoriaMetrics Ecosystem Production Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `000015` Operational Asset Catalog 与 `000016` Connection Publication 基础上，完成 VictoriaMetrics Operator、VictoriaMetrics、VictoriaLogs、VictoriaTraces 的生产级资产发现、版本兼容、类型化只读调查、证据治理、前端体验与运维闭环。

**Architecture:** Operator 发现层只产生安全投影并复用统一资产目录；连接契约在服务端固定租户路由、Target/Connector/Evidence/Executor 版本闭包；独立只读执行器只实现明确列出的查询端点，并在证据进入控制平面前执行 schema、预算与 DLP 校验。旧 runtime bundle N 与新 bundle N+1 同时可运行，兼容性不明确时关闭能力而不阻止资产可见。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Kubernetes client-go v0.36.2、VictoriaMetrics Operator v0.73.1、VictoriaMetrics v1.147.0、VictoriaLogs v1.51.0、VictoriaTraces v0.9.4、React 19.2.7、TypeScript 7.0.2、TanStack Query、Vitest、MSW、Playwright、axe-core、Prometheus/OpenTelemetry。

## Global Constraints

- 本阶段目标是生产闭环基础，不是 demo；不得用静态 fixture、内存 fake 或前端硬编码代替生产路径。
- migration 编号固定为 `000017_victoriametrics_ecosystem`；不得改写 `000015`、`000016` 的历史文件。
- 所有持久对象、查询与缓存键都包含 `tenant_id/workspace_id/environment_id`；任何跨 Scope 访问必须稳定拒绝。
- 发现层覆盖 Operator 当前公开的 21 种资源，并将长期运行组件、配置 CRD、工具制品分开建模。
- `VMUser` 及 Operator 生成的 `vmuser-{name}` Secret 只能投影为 Opaque Credential Reference；发现进程的 RBAC、请求日志、缓存和测试都不得读取 Secret 内容。
- `VMAnomaly` 本阶段只有资产、关系、健康信息；不得编译或发布任何写入、训练、回放或配置变更能力。
- 只开放本计划列出的 Metrics、Logs、Traces 类型化只读能力；`vminsert`、`vlinsert`、`vtinsert`、OTLP、导入、删除、`vmctl`、`vmbackup`、`vmrestore`、`vmalert-tool` 永远不进入调查能力集合。
- Tenant 由 Connection Contract 服务端拥有；任务、模型、浏览器、公共 API 和 evidence 都不得提交或回显 `AccountID`、`ProjectID`、租户路径或租户头。
- Target schema、Connector schema、Evidence schema、Executor profile 必须形成精确版本闭包；未知版本只保留资产可见性，能力状态为 `UNSUPPORTED`。
- 输出在进入控制平面前必须通过严格 JSON schema、深度/数量/字节预算、稳定排序、JCS/SHA-256 和 DLP；不接受 partial response。
- 所有新增行为严格 TDD：先写失败测试并运行确认，再做最小实现，再运行通过；每个 Task 独立提交。
- 实现时先确认基线为 `main@ad50d9f`；若前序包已推进，必须以已合入接口为准做适配并记录差异，不可回退用户或其他任务的修改。

---

## Execution Order

| 顺序 | Task pack | 核心产物 | 前置 |
|---|---|---|---|
| 1 | [`01-taxonomy-schema.md`](./01-taxonomy-schema.md) | `000017`、完整 taxonomy、兼容矩阵、服务端租户契约 | Phase 1、Phase 2 |
| 2 | [`02-operator-discovery.md`](./02-operator-discovery.md) | 21 CRD 安全投影、拓扑关系、HA 发现 worker、Secret 零读取 | Pack 01 |
| 3 | [`03-metrics-logs-contracts.md`](./03-metrics-logs-contracts.md) | Metrics/Logs 12 个类型化只读能力与负向入口封锁 | Pack 01、Phase 2 runtime |
| 4 | [`04-traces-runtime.md`](./04-traces-runtime.md) | Traces 6 个只读能力、DLP、N/N+1 runtime 发布 | Pack 03 |
| 5 | [`05-api-web.md`](./05-api-web.md) | 安全公共投影、Victoria 生态资产/连接/能力 UI | Packs 01–04 |
| 6 | [`06-e2e-operations-docs.md`](./06-e2e-operations-docs.md) | 后端/浏览器 E2E、HA、指标、告警、runbook、ADR | Packs 01–05 |

同一 pack 内按 Task 编号串行执行；只在文件集合无重叠、接口已经固定时并行。每个 pack 完成后先运行该文件末尾的包级 gate，再进入下一包。

## Fixed Taxonomy

### Long-lived runtime assets

| Family | Asset kinds |
|---|---|
| Metrics | `VICTORIAMETRICS_SINGLE`, `VICTORIAMETRICS_CLUSTER`, `VICTORIAMETRICS_VMSELECT`, `VICTORIAMETRICS_VMINSERT`, `VICTORIAMETRICS_VMSTORAGE` |
| Logs | `VICTORIALOGS_SINGLE`, `VICTORIALOGS_CLUSTER`, `VICTORIALOGS_VLSELECT`, `VICTORIALOGS_VLINSERT`, `VICTORIALOGS_VLSTORAGE` |
| Traces | `VICTORIATRACES_SINGLE`, `VICTORIATRACES_CLUSTER`, `VICTORIATRACES_VTSELECT`, `VICTORIATRACES_VTINSERT`, `VICTORIATRACES_VTSTORAGE` |
| Agents/control | `VMAGENT`, `VLAGENT`, `VMALERT`, `VMAUTH`, `VMGATEWAY`, `VMALERTMANAGER`, `VMANOMALY`, `VMOPERATOR`, `VMBACKUPMANAGER` |

### Configuration-only CRD assets

`VMRULE`, `VMUSER`, `VMALERTMANAGER_CONFIG`, `VMNODE_SCRAPE`, `VMPOD_SCRAPE`, `VMPROBE`, `VMSERVICE_SCRAPE`, `VMSTATIC_SCRAPE`, `VMSCRAPE_CONFIG`。

配置资产可参与 `CONFIGURES`、`SELECTS`、`OWNED_BY` 等关系，但不得拥有 Query Target 或调查能力。

### Tool artifacts

`VMCTL`, `VMBACKUP`, `VMRESTORE`, `VMALERT_TOOL`。

工具制品只记录版本、来源、digest 与归属关系；不得从容器名或镜像字符串推断可执行权限。

## Official Operator Coverage

发现目录必须逐项声明并测试以下 21 种公开资源：

1. `VMAgent`
2. `VMAnomaly`
3. `VMAlert`
4. `VMAlertManager`
5. `VMAlertManagerConfig`
6. `VMAuth`
7. `VMCluster`
8. `VMNodeScrape`
9. `VMPodScrape`
10. `VMProbe`
11. `VMRule`
12. `VMServiceScrape`
13. `VMStaticScrape`
14. `VMSingle`
15. `VMUser`
16. `VMScrapeConfig`
17. `VLSingle`
18. `VLAgent`
19. `VLCluster`
20. `VTSingle`
21. `VTCluster`

服务端通过 Kubernetes API discovery 选择 served API version；优先 `operator.victoriametrics.com/v1`，兼容仍被集群提供的 `v1beta1`，禁止假设所有集群只存在单一版本。

## Fixed Read-only Capability Matrix

| Capability | Operation | Exact upstream endpoint | Dynamic task input |
|---|---|---|---|
| `VICTORIAMETRICS_INSTANT_QUERY` | `instant_query` | `/api/v1/query` | `evaluation_offset_seconds` |
| `VICTORIAMETRICS_RANGE_QUERY` | `range_query` | `/api/v1/query_range` | `lookback_seconds` |
| `VICTORIAMETRICS_LABEL_NAMES` | `label_names` | `/api/v1/labels` | `lookback_seconds` |
| `VICTORIAMETRICS_LABEL_VALUES` | `label_values` | `/api/v1/label/{label_name}/values` | `lookback_seconds` |
| `VICTORIAMETRICS_CLUSTER_HEALTH` | `cluster_health` | `/health` | none |
| `VICTORIAMETRICS_CAPACITY_SNAPSHOT` | `capacity_snapshot` | `/api/v1/status/tsdb` | none |
| `VICTORIALOGS_SEARCH` | `search` | `/select/logsql/query` | `lookback_seconds` |
| `VICTORIALOGS_HITS` | `hits` | `/select/logsql/hits` | `lookback_seconds` |
| `VICTORIALOGS_FACETS` | `facets` | `/select/logsql/facets` | `lookback_seconds` |
| `VICTORIALOGS_STATS_RANGE` | `stats_range` | `/select/logsql/stats_query_range` | `lookback_seconds` |
| `VICTORIALOGS_FIELD_VALUES` | `field_values` | `/select/logsql/field_values` | `lookback_seconds` |
| `VICTORIALOGS_CLUSTER_HEALTH` | `cluster_health` | `/health` | none |
| `VICTORIATRACES_LIST_SERVICES` | `list_services` | `/select/jaeger/api/services` | none |
| `VICTORIATRACES_LIST_OPERATIONS` | `list_operations` | `/select/jaeger/api/services/{service_name}/operations` | `service_name` from definition allowlist |
| `VICTORIATRACES_FIND_TRACES` | `find_traces` | `/select/jaeger/api/traces` | `lookback_seconds` |
| `VICTORIATRACES_GET_TRACE` | `get_trace` | `/select/jaeger/api/traces/{trace_id}` | lowercase 16/32-hex `trace_id` |
| `VICTORIATRACES_DEPENDENCIES` | `dependencies` | `/select/jaeger/api/dependencies` | `lookback_seconds` |
| `VICTORIATRACES_CLUSTER_HEALTH` | `cluster_health` | `/health` | none |

Query expression、LogsQL、label name、field name、service/operation filter、tag allowlist、limit、step、topN、projection 和上游路径全部来自已发布 Capability Definition，不接受模型自由文本。

## Target Eligibility

| Asset role | Asset visible | Health | Query capability | Reason |
|---|---:|---:|---:|---|
| Single / select component | yes | yes | yes when compatible | bounded read surface |
| `vmauth` / `vmgateway` governed query route | yes | yes | yes when route profile exact | fixed proxy route only |
| insert / OTLP component | yes | yes | no | ingestion endpoint |
| storage component | yes | yes | no | admin/storage surface |
| Agent / alerting / anomaly | yes | selected health | no | not a query target |
| Configuration CRD | yes | no | no | declarative configuration only |
| Tool artifact | yes | no | no | offline/admin tool |

## Version Compatibility Closure

首个已验证 profile 固定为：

```text
Operator:       0.73.1
VictoriaMetrics: 1.147.0
VictoriaLogs:    1.51.0
VictoriaTraces:  0.9.4
Kubernetes API:  served operator.victoriametrics.com/v1 or v1beta1
```

该 profile 不是宽泛 semver 承诺。发现到其他版本时仍创建资产和版本证据，但 Connection validation、Capability compile 与 Runtime publication 必须返回 `CAPABILITY_PROFILE_INCOMPATIBLE`，直到新增 profile 经过契约与真实服务测试并发布。

每次执行必须匹配同一闭包：

```text
ConnectionContractRevision
  -> CompatibilityProfileRevision
  -> TargetSchemaVersion
  -> ConnectorSchemaVersion
  -> EvidenceSchemaVersion
  -> ExecutorProfileDigest
  -> AppliedRuntimePublicationDigest
```

闭包任一成员缺失、撤销、drift 或 digest 不一致都停止执行。

## Tenant Route Contract

- Single-node Metrics 使用固定 `/api/v1/*` 路由，租户固定为 `0:0`，公共投影只显示 `SINGLE_DEFAULT`。
- Metrics cluster 默认使用 `/select/{account[:project]}/prometheus/*`；只有 compatibility profile 明确允许 v1.143.0+ header mode 时，才使用 `/select/prometheus/*` 与服务端注入头。
- Logs 与 Traces 使用服务端注入的 `AccountID`、`ProjectID`，值必须为 `0..4294967295` 的十进制无符号整数。
- Governed `vmauth`/`vmgateway` 只使用内容寻址的固定 route profile；禁止任意 path/header 模板。
- Public API、日志、metric label、审计详情和 evidence 只暴露 `tenant_route_mode` 与 contract digest，不暴露实际 tenant value。

## Evidence Safety Contract

每个 operation 使用独立 JSON Schema。共同约束：

```text
max_duration_seconds: 1..20
max_result_items:      1..1000
max_result_bytes:      1024..1048576
max_json_depth:        12
max_string_bytes:      4096
partial_response:      forbidden
content_encoding:      identity
canonicalization:      RFC 8785 JCS
digest:                lowercase SHA-256
```

DLP 在 isolated read executor 内、写入 artifact 或 completion 之前执行。检测到 bearer/token/password/private-key/cookie/session/DSN/credential URI、未允许的邮箱/IP/customer identifier、超长 tag/log 字段或 secret-like key 时返回固定低敏错误码；错误和指标不得包含命中原文。

## Runtime N / N+1 Rule

- 保留当前 `read-executor-profile.v1` 与 digest `d776a2e45f33496a8a2558fba82096064c3aed10be588627a337e70983485e63`，保证已发布 bundle N 可继续执行。
- 新 Victoria 能力通过新 profile digest 和 registry 引入，不覆盖 singleton 构造结果，也不修改旧 connector manifest bytes。
- N+1 只有在 validation 通过、兼容闭包完整、artifact digest 核对且 rollout status=`APPLIED` 后才可接收新 grant。
- Rollback 只切回已验证且仍未撤销的 N；不得把 N+1 task 用 N profile 执行。

## Artifact Ownership and Source of Truth

| Concern | Authoritative artifact | Derived projections | Never authoritative |
|---|---|---|---|
| Asset identity/lifecycle | Phase 1 `assets` + current observation | API/UI Victoria summary | Kubernetes display label alone |
| Operator source | exact published Phase 1 `asset_source_revisions` + 1:1 `victoria_operator_source_revisions` typed extension | discovery worker config | process environment snapshot |
| Taxonomy | Go literal catalog + `assets_kind_check` | filter labels/badges | image/name prefix inference |
| Product topology | exact UID relationship graph | accessible topology/read model | UI graph coordinates |
| Version support | published Compatibility Profile revision | supported/unsupported reason | loose semver or newest image |
| Tenant routing | private Connection Contract revision | route mode + digest | task/browser/model input |
| Credential | Credential Reference revision | opaque ID/revision/status | Secret value/name in asset doc |
| Query semantics | Capability Definition revision | human description/budgets | prompt/free-form input |
| Target security | compiled private Target artifact | safe security summary | endpoint fields in public API |
| Runtime behavior | executor profile digest | publication/profile status | mutable “latest” selector |
| Evidence | schema-valid canonical artifact + digest | bounded public summary | raw upstream response |
| UI contract | OpenAPI + generated `web/src/shared/api/schema.d.ts` | React view models | handwritten duplicate types |
| Interaction design | `docs/design/frontend/victoriametrics-ecosystem.md` | components/CSS/tests | screenshots without rationale |
| Operational readiness | exercised runbooks + stage status evidence | dashboard/alerts | an unverified readiness claim |

每个 derived projection 都必须能追溯到 stable ID、revision 和 digest，但不得借此暴露私有内容。若同一信息在多个来源不一致，以表中 authoritative artifact 为准，并将其他 projection 标记 drift，而不是静默覆盖。

## Cross-package Handoff Contract

Pack 01 hands Pack 02 a closed taxonomy and published source revision；Pack 02 only emits Phase 1 NormalizedItem/relationships and never creates a Connection. Packs 03–04 consume published definitions/contracts and emit runtime artifacts/evidence，never mutate discovery data. Pack 05 reads public projections only；Pack 06 verifies the same production assembly and records evidence.

The minimum handoff tuple is:

```text
scope
asset_id + asset_version
connection_id + connection_revision
compatibility_profile_id + revision + digest
target_id + schema_version + digest
capability_definition_id + revision + digest
connector_id + schema_version + digest
evidence_schema_version + digest
executor_profile_digest
runtime_publication_id + digest + APPLIED status
```

缺少任一成员时，调用方返回固定关闭原因，不能自行补默认值。Scope、Asset version 与所有 revision/digest 必须在每次 admission 和 execution 重新核对；缓存只可保存内容寻址对象，撤销/kill-switch 状态不能被缓存掩盖。

## Deliberately Deferred Beyond Phase 3

- Phase 4 才建立主动调查 policy、Snapshot、Grant、预算和四边界 authorization；Phase 3 不自行授予调查权限。
- Host/PostgreSQL 专项资产与查询属于后续 migration，不混入 Victoria capability。
- Production platform promotion、跨区域灾备和 release governance 在后续阶段完成；本阶段只交付可验证基础与本地/CI 演练。
- 任何写入、变更、删除、重启、扩缩容、备份恢复执行、告警规则修改和 VMAnomaly 训练均不在本阶段能力集合。
- 未经 profile 测试的未来 Operator/产品版本只发现，不开放能力；版本升级按 Pack 06 runbook 新增 profile revision。

## Stable Error Codes

| Code | Meaning |
|---|---|
| `VICTORIAMETRICS_RESOURCE_UNSUPPORTED` | GVR、资源或 role 不在固定目录 |
| `VICTORIAMETRICS_VERSION_UNSUPPORTED` | 产品或 Operator 版本没有已发布 profile |
| `CAPABILITY_PROFILE_INCOMPATIBLE` | Target/Connector/Evidence/Executor 闭包不匹配 |
| `VICTORIAMETRICS_TENANT_ROUTE_MISMATCH` | 服务端租户路由与 profile 不一致 |
| `VICTORIAMETRICS_INGESTION_ENDPOINT_FORBIDDEN` | 请求触及 insert/OTLP/import/write/delete 路由 |
| `VICTORIAMETRICS_PARTIAL_RESPONSE_REJECTED` | 上游返回或请求允许 partial data |
| `VICTORIAMETRICS_EVIDENCE_DLP_REJECTED` | evidence 命中 DLP 或安全 schema |

这些错误可以带 `operation_id`、`asset_id`、`profile_digest` 与固定检查名；不得带 endpoint、tenant、query、header、credential、原始 evidence 或 Kubernetes object bytes。

## Frontend Information Architecture

不新增含糊的 “VM” 一级概念。复用稳定路由：

- `/assets`：增加“VictoriaMetrics 生态”保存视图、Family/Topology/Taxonomy/Capability filter。
- `/assets/$assetId`：增加概览、拓扑、版本兼容、连接与能力、安全边界、关系 tab。
- `/connections`：增加 VictoriaMetrics / VictoriaLogs / VictoriaTraces provider filter 与受支持 target role。
- `/connections/new`：仅选择 Provider 并创建服务端 `DRAFT`，随后 replace 到 canonical ID/revision 六步向导；向导只选择服务端验证出的 route mode，永远不提供自由 tenant/path/header 输入。
- `/capabilities`：显示 18 个只读 capability、schema/profile digest、预算和关闭原因。

在 1440px、1024px、390px 宽度下必须可操作；键盘焦点、错误摘要、状态非颜色表达和 WCAG 2.2 AA 对比度由组件测试与 axe 覆盖。

## Production Acceptance Gates

- `TestOperatorResourceCoverage` 证明 21 个 Operator 资源无缺失、无重复并覆盖 served API version。
- `TestSecretProjectionDenied` 证明 RBAC、HTTP 请求、缓存、日志、NormalizedItem、API/前端 fixture 都不含 Secret 内容。
- `TestVictoriaMetrics*`、`TestVictoriaLogs*`、`TestVictoriaTraces*` 覆盖全部 18 个能力及成功、预算、DLP、tenant、partial、ingestion/tool 负向路径。
- PostgreSQL migration up/down/up、Scope FK、不可变 revision、兼容闭包和 down guard 在真实 PostgreSQL 通过。
- 发现 worker 双实例 lease/fencing、watch 断线 relist、complete snapshot、重复事件幂等和未知版本 fail-closed 通过。
- bundle N 与 N+1 并行执行、drift 停止、新 grant 只进 APPLIED N+1、rollback 回 N 的测试通过。
- OpenAPI generated client 无漂移；公共响应、浏览器网络记录和 artifact 不出现 tenant value 或 credential material。
- Playwright 明确区分“虚拟机”与“VictoriaMetrics 生态”，并覆盖 query-capable、asset-only、config-only、tool-only、unsupported 五种状态。
- 指标、告警、dashboard、HA/容量/恢复/升级/撤销 runbook 与 ADR 完成，演练记录可由 CI 生成。

## Authoritative References

- [VictoriaMetrics Operator resources](https://docs.victoriametrics.com/operator/resources/)
- [VMUser resource and generated Secret](https://docs.victoriametrics.com/operator/resources/vmuser/)
- [VictoriaMetrics Operator changelog](https://docs.victoriametrics.com/operator/changelog/)
- [VictoriaMetrics query API](https://docs.victoriametrics.com/victoriametrics/)
- [VictoriaMetrics cluster API](https://docs.victoriametrics.com/victoriametrics/cluster-victoriametrics/)
- [VictoriaLogs querying](https://docs.victoriametrics.com/victorialogs/querying/)
- [VictoriaTraces querying](https://docs.victoriametrics.com/victoriatraces/querying/)
- [VMCluster operator resource](https://docs.victoriametrics.com/operator/resources/vmcluster/)
- [VLCluster operator resource](https://docs.victoriametrics.com/operator/resources/vlcluster/)
- [VTCluster operator resource](https://docs.victoriametrics.com/operator/resources/vtcluster/)

## Final Program Command

所有 task pack 完成后从仓库根目录运行：

```bash
go test ./... -count=1
go test -race ./internal/assetdiscovery/victoriametrics ./internal/readconnector ./internal/readexecutor ./internal/readruntime -count=1
go vet ./...
go test ./internal/store/postgres -run 'TestVictoriaMetricsEcosystemMigration' -count=1
pnpm --dir web lint
pnpm --dir web typecheck
pnpm --dir web test -- --run
pnpm --dir web build
pnpm --dir web test:e2e -- --project=chromium
git diff --check
```

Expected: 全部退出码为 0；无 generated OpenAPI 漂移、无跳过的 security/E2E test、无待办标记或占位实现。
