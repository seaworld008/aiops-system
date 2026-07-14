# 规范到实施计划覆盖矩阵

本矩阵用于证明[已确认设计规范](../../specs/2026-07-13-operational-assets-controlled-access-design.md)的每项要求都有唯一实施入口和生产验收出口。它只做追踪，不替代[总实施计划](../2026-07-13-governed-operations-program.md)、[版本基线](version-baseline.md)或各任务包。

## 规范章节覆盖

| 规范章节 | 主实施阶段 | 生产证明 |
|---|---|---|
| 1–2 摘要、当前事实与动机 | [总实施计划](../2026-07-13-governed-operations-program.md)、[阶段总索引](README.md) | V4 继承/替代图与最终状态源 |
| 3 核心概念与最高不变量 | [Phase 1](01-assets/README.md)、[Phase 4](04-proactive-grants/README.md)、[Phase 7](07-governed-actions/README.md) | 身份、范围、快照、计划、凭据、验证、审计全链负向测试 |
| 4 四层架构 | [Phase 1](01-assets/README.md)、[Phase 2](02-connections/README.md)、[Phase 4](04-proactive-grants/README.md)、[Phase 6](06-production-platform/README.md)、[Phase 7](07-governed-actions/README.md) | 真实 Control Plane/Gateway/READ-WRITE Runner/credential/Temporal 双修订装配 |
| 5 资产目录 | [Phase 1](01-assets/README.md)，尤其 [Source/API](01-assets/05-source-ingestion-csv-api.md)、[CMDB](01-assets/06-source-external-cmdb.md)、[vSphere](01-assets/07-source-vsphere.md)、[云/虚拟化](01-assets/08-source-proxmox-openstack-cloud.md)、[Discovery Worker](01-assets/09-discovery-worker-ha-e2e.md) | 十表 PostgreSQL、不可变 authority child、三摘要 PostgreSQL 重算/direct-SQL/恢复负向证据、真实 Provider、发现合并、映射治理、OIDC/API/UI、HA/E2E、逐 Provider gate |
| 6 VictoriaMetrics 全家桶 | [Phase 3](03-victoriametrics/README.md) | Operator 全资源投影、Metrics/Logs/Traces 类型化 READ、ingestion/tool 零能力 |
| 7 主机、远程方式与数据库 | [Phase 5](05-host-postgresql/README.md)，[Provider 发布](05-host-postgresql/02-provider-publication-runtime.md)、[API/Web/E2E](05-host-postgresql/03-provider-api-web-e2e.md)、[AWX enrollment](../../../contracts/awx-host-identity-enrollment-v1.md)、[governed launch](../../../contracts/awx-governed-launch-admission-v1.md)、[host attestor](../../../contracts/host-identity-attestor-v1.md) | Host Probe/AWX/PostgreSQL 三 Provider 全 Connection/Runtime 链、mapping-only→enrollment→N+1 identity、serializable governed Job admission、hardware-backed host identity、固定诊断、READ credential、DLP |
| 8 ConnectionProfile 与发布 | [Phase 2](02-connections/README.md)，[连接向导](02-connections/06-web-publication-flow.md)、[凭据/Realm 库存](02-connections/07-governance-inventory-web.md) | 六步修订/验证/发布、mTLS Validation Runner、Runtime N/N+1、安全凭据引用/Realm/binding 库存 |
| 9 InvestigationGrant 与主动策略 | [Phase 4](04-proactive-grants/README.md)，[ActionProposal](04-proactive-grants/04-evidence-action-proposal.md)、[Investigation/Policy Hub](04-proactive-grants/06-investigation-policy-hub.md) | 事件/定时触发、短 Grant、预算、六级 Kill Switch、四边界复验、无执行权 Proposal/Finding 与人工 Phase 7 handoff |
| 10 持久化模型 | Phase 1–8 各自 migration 包 | `000015`–`000022` 顺序迁移、跨 Scope FK、不可变记录与回滚测试 |
| 11 后端模块与 RunnerRealm | [Phase 2](02-connections/README.md)、[Phase 3](03-victoriametrics/README.md)、[Phase 5](05-host-postgresql/README.md)、[Phase 7](07-governed-actions/README.md) | Validation/READ/WRITE Realm、身份、队列、issuer 和 egress 隔离 |
| 12 公共 API | Phase 1–5 API 包、[Overview](01-assets/10-overview-control-room.md)、[治理库存](02-connections/07-governance-inventory-web.md)、[ActionProposal](04-proactive-grants/04-evidence-action-proposal.md)、[Incident/Audit](07-governed-actions/05-incident-audit-workspace.md)、[Action API](07-governed-actions/06-api-web-operator-journey.md)、Phase 8 release API | 单一 OpenAPI、Problem Details、幂等/ETag、生成类型无漂移、无平行 DTO/路由；ActionPlan create 固定 full T/W/E/S path + 六字段 closed body + header Idempotency-Key |
| 13 权限 | [Phase 1](01-assets/03-mapping-auth-api.md)、[Phase 2 库存](02-connections/07-governance-inventory-web.md)、[Phase 4](04-proactive-grants/03-gateway-api.md)、[Phase 5 Diagnostics](05-host-postgresql/07-api-web.md)、[Incident/Audit](07-governed-actions/05-incident-audit-workspace.md)、[Phase 7](07-governed-actions/02-policy-approval-reauth.md) | API `effective_actions`、Scope 隔离、独立 READ/RUN/CANCEL、reauth、职责分离 |
| 14 前端产品设计 | [Phase 1 Foundation/Assets](01-assets/04-web-foundation-assets.md)、[Overview](01-assets/10-overview-control-room.md)、[Connections](02-connections/06-web-publication-flow.md)、[凭据/Realm](02-connections/07-governance-inventory-web.md)、[Victoria](03-victoriametrics/05-api-web.md)、[Investigation/Policy](04-proactive-grants/06-investigation-policy-hub.md)、[Diagnostics](05-host-postgresql/07-api-web.md)、[Incident/Audit](07-governed-actions/05-incident-audit-workspace.md)、[Action Workspace](07-governed-actions/06-api-web-operator-journey.md)、[Release Web](08-production-rollout/05-staged-rollout-slos.md) | 低 AI 感高保真控制台、持久设计文档、真实 OIDC、响应式、Playwright/axe |
| 15 正交状态模型 | Phase 1–7 领域/API/Web 任务包 | 生命周期、映射、连接、能力、Grant、执行、验证状态独立投影 |
| 16 错误与停止条件 | [Phase 4](04-proactive-grants/README.md)、[Phase 5](05-host-postgresql/README.md)、[Phase 7](07-governed-actions/README.md)、[Phase 8](08-production-rollout/README.md) | drift/expiry/revocation/uncertainty 均 stop、清理、对账或人工升级 |
| 17 审计与可观测性 | 每阶段 E2E/Operations 包 | 事务 Outbox、不可变 Evidence/Receipt/Audit、SLO/告警/Runbook |
| 18 威胁模型 | 各阶段负向套件、[Phase 8 安全合规](08-production-rollout/04-security-compliance.md) | 机密面、越权、重放、Realm 混淆、供应链、恢复与发布滥用测试 |
| 19 测试与验收 | 每个任务包的 TDD/commit 步骤 | Go/race/PostgreSQL/OpenAPI/Web/E2E/安全/恢复/灰度证据 |
| 20 迁移与交付拆分 | [总实施计划](../2026-07-13-governed-operations-program.md) | 八个阶段门和 `SPEC_APPROVED → PRODUCTION_CLOSED_LOOP_ACCEPTED` 状态机 |
| 21 非目标 | 各任务包 Global Constraints | 任意 shell/SQL/endpoint/payload、交互终端、ingestion、通用写代理均不存在 |
| 22 文档持久化 | [Phase 8 最终交接](08-production-rollout/06-ownership-runbooks-final-e2e.md) | status、V4 小章节、ADR、frontend、OpenAPI、AGENTS、Runbook 合同测试 |

## 运维资产与连接覆盖

| 资产/数据源 | 资产治理 | 连接与运行能力 | Agent 可执行边界 |
|---|---|---|---|
| 虚拟机、Linux/Windows 主机 | Phase 1 手工/CSV/API/CMDB/vSphere/Proxmox/OpenStack/AWS/Azure/GCP 来源、关系、provenance、生命周期 | Phase 5 Host Probe 或已发布 AWX 模板 | 固定只读诊断；无 SSH/WinRM 交互、PTY、命令、脚本、转发或 SFTP |
| VictoriaMetrics/Logs/Traces | Phase 3 Operator CRD、配置、工具和服务资产 | Phase 2 Connection + Phase 3 typed Target/Capability | Query-only；无 `vminsert`/`vlinsert`/`vtinsert`/OTLP、备份工具或任意 URL |
| PostgreSQL | Phase 1/5 数据库资产与实例关系 | Phase 2 Connection + Phase 5 named query/runtime | 只读事务、固定查询/参数/预算/DLP；无任意 SQL、DDL/DML/COPY/函数 |
| Kubernetes/GitOps/AWX 写目标 | Phase 1–2 exact Asset/Connection/Runtime | Phase 7 单 Action 类型 publication | 不可变计划、策略、reauth、审批、短 WRITE credential、独立验证 |
| 其他数据库、云、网络、DNS、Secret 系统 | 可先作为资产登记 | 只有独立 Provider 契约通过后才发布 | 默认无 Capability；不得借用通用 endpoint/payload 执行 |

## Source Provider 生产门覆盖

| Source/Profile | 实施包 | 独立生产证据 | 未验收状态 |
|---|---|---|---|
| `MANUAL` | [Phase 1 基础资产](01-assets/04-web-foundation-assets.md) | OIDC/Scope/ETag/Idempotency/Audit；只登记引用 | 不进入 Discovery Worker |
| `CSV_RFC4180_V1` / `API_BATCH_V1` | [CSV/API](01-assets/05-source-ingestion-csv-api.md) | 签名或 mTLS/JWS、stream/sequence、DLP、checkpoint、HA/cleanup | `UNAVAILABLE` |
| `CMDB_CATALOG_V1` | [External CMDB](01-assets/06-source-external-cmdb.md) | 身份/TLS/只读协议、增量/关系/provenance、staging canary | `UNAVAILABLE` |
| `VSPHERE_VCENTER_V1` | [vSphere](01-assets/07-source-vsphere.md) | vCenter UUID/TLS/最小权限、SOAP full+delta、lab canary | `UNAVAILABLE` |
| `PROXMOX_VE_V1` / `OPENSTACK_NOVA_V2_1` | [虚拟化/云](01-assets/08-source-proxmox-openstack-cloud.md) | authority identity、只读分页/快照、缺失/恢复、lab canary | `UNAVAILABLE` |
| `AWS_EC2_V1` / `AZURE_COMPUTE_V1` / `GCP_COMPUTE_V1` | [虚拟化/云](01-assets/08-source-proxmox-openstack-cloud.md) | workload identity、逐账号/订阅/项目分页、配额/HA、sandbox canary | `UNAVAILABLE` |
| `KUBERNETES_OPERATOR` | [Phase 3 Operator](03-victoriametrics/02-operator-discovery.md) | 21 CRD、Secret 零读取、watch/relist/fence、兼容 profile | Phase 1 显式 `UNAVAILABLE` |
| `AWX_INVENTORY` | [Phase 5 Provider Runtime](05-host-postgresql/02-provider-publication-runtime.md) | exact AWX Runtime、cursor/fence/429/provenance/full reconcile | Phase 1 显式 `UNAVAILABLE` |

Source kind、SDK 或注册表条目本身不是开门证据；Gate 必须绑定 exact Scope、Source/Profile/Revision、Credential/Runtime binding 和未过期签名 receipt。

### Future Source gate successor 证据

唯一 hook identity 固定为 `public.asset_catalog_future_source_gate_admitted(candidate public.asset_sources) RETURNS boolean`；Phase 1 默认 body 由 deferred Source INSERT closure 用于阻止 K8S/AWX 初始 commit，并由 mutation trigger 用于阻止 `VALIDATING|AVAILABLE|DEGRADED`。即使 successor creation branch 返回 true，INSERT closure 也要求 commit 时 Source 仍为 exact initial `UNAVAILABLE` + revision-1 `DRAFT` shape；create+validate/publish/open 同一事务必须回滚，后续阶段各用新的 serializable transaction。已有 Source 向 `UNAVAILABLE|SUSPENDED` 收敛在 generic normalization 后不调用 hook。后续 owned migration 只能 `CREATE OR REPLACE` 同签名 body，必须分别证明 same-transaction initial creation、pre-validation 与 terminal-live closure；每次替换前后验收 definition/owner/ACL/no-overload，所有创建/开门路径使用 `SERIALIZABLE` 与固定锁序，所有可变依赖事实的反向变更在同一锁序下原子关闭依赖 Source，禁止 enum/registry 推断、第二套 Go predicate或检查后漂移。

| Migration / owner | Exact admitted closure | Positive evidence | Negative / drift evidence | Recovery / down evidence |
|---|---|---|---|---|
| `000015` / [Phase 1 schema](01-assets/01-schema-domain.md) | 无；K8S/AWX initial `UNAVAILABLE` creation 与 `VALIDATING|AVAILABLE|DEGRADED` 均默认 false；仅已有 Source 向 `UNAVAILABLE|SUSPENDED` 收敛不调用 hook | definition、role-independent owner/ACL、signature/default-false body/no-overload 纳入 reviewed manifest；existing `SUSPENDED/UNAVAILABLE` convergence fail-close positive | enum、Provider/Profile registry、published revision 或单独 validation row 都不能越过 initial creation closure 或 `asset_sources_future_phase_gate_guard`；非-serializable live transition/NULL hook 均拒绝 | up/down/up 后仍 default false；仅 owned successor migration 可替换 body |
| `000017` / [Victoria schema](03-victoriametrics/01-taxonomy-schema.md)、[Operator worker](03-victoriametrics/02-operator-discovery.md) | `VALIDATING`：exact K8S/profile/schema/typed extension/queued validation；`AVAILABLE|DEGRADED`：再加 published revision、successful proof+cleanup；AWX false | pre-validation positive 仅进入 VALIDATING，terminal positive 才开门；固定锁序下 hook 重查；reviewed admission/dump-restore 保持 definition/owner/ACL | wrong profile/schema、extension/base digest、revision、validation/cleanup drift 在首个 Kubernetes call 前 fail closed；若并发双方提交则漂移方已原子关门，否则一方 serialization failure | 只能新 immutable typed extension revision 重新验证/发布恢复；down 遇任一 K8s Source（含 `UNAVAILABLE|SUSPENDED`）即拒绝，先恢复 `000015` body/manifest 再删 extension |
| `000019` / [Host/PostgreSQL schema](05-host-postgresql/01-host-assets-contracts.md)、[AWX Runtime](05-host-postgresql/02-provider-publication-runtime.md) | 完整保留 `000017` 分状态 K8s branch；AWX `VALIDATING` 需要 exact profile/Integration/唯一 Runtime/queued validation，live branch 再加 published revision、successful proof+cleanup | predecessor 全 surface 验收与 K8s truth-table；AWX pre-validation/live fixtures；SERIALIZABLE 固定锁序；reviewed admission/dump-restore 保持 definition/owner/ACL | registry/Runtime row alone false；wrong profile/schema、cross-Scope Integration、missing/duplicate Runtime、Connection/Bundle/attestation/published/validated digest 或并发漂移在首个 AWX HTTP call 前 fail closed | down 遇任一 AWX Source（含 closed）即拒绝；仅从未创建 AWX Source 的空状态可恢复 exact `000017` body，重装后只能创建全新的 Source/revision/Runtime/proof |

## 前端页面与持久设计覆盖

| 页面/路由 | 实施入口 | 持久设计事实源 |
|---|---|---|
| `/overview` | [Overview Control Room](01-assets/10-overview-control-room.md) | `docs/design/frontend/overview.md` |
| `/assets`、`/assets/$assetId`、`/asset-mappings` | [Foundation/Assets](01-assets/04-web-foundation-assets.md) | `docs/design/frontend/foundation-assets.md` |
| `/asset-sources` | [Source Workspace](01-assets/05-source-ingestion-csv-api.md) | `docs/design/frontend/asset-sources.md` |
| `/connections`、`/connections/new`、canonical revision | [Connection Web](02-connections/06-web-publication-flow.md) | `docs/design/frontend/connections-runtime.md` |
| `/credential-references`、`/runner-realms` | [Governance Inventory](02-connections/07-governance-inventory-web.md) | `docs/design/frontend/credential-references-runner-realms.md` |
| Victoria 资产/连接/能力视图 | [Victoria Web](03-victoriametrics/05-api-web.md) | `docs/design/frontend/victoriametrics-ecosystem.md` |
| `/proactive-policies`、`/investigations`、`/governance/policies` | [Phase 4 Web](04-proactive-grants/05-web-experience.md)、[Hub](04-proactive-grants/06-investigation-policy-hub.md) | `proactive-investigation.md`、`investigation-policy-hub.md` |
| Asset “固定诊断”与运行深链 | [Diagnostics Web](05-host-postgresql/07-api-web.md) | `host-postgresql-diagnostics.md` |
| `/platform/readiness`、`/platform/dependencies`、`/platform/realms`、`/platform/runtime`、`/platform/slo`、`/platform/rollouts/$rolloutId` | [Read Platform Console](06-production-platform/05-shadow-readonly-rollout.md) | `production-read-platform.md` |
| `/incidents`、`/audit`、`/action-plans` | [Incident/Audit](07-governed-actions/05-incident-audit-workspace.md)、[Governed Actions](07-governed-actions/06-api-web-operator-journey.md) | `incident-workspace.md`、`audit-explorer.md`、`governed-actions.md` |
| `/production/releases` | [Release Command Center](08-production-rollout/05-staged-rollout-slos.md) | `production-release-command-center.md` + Phase 8 frontend compendium |

所有页面共享 Phase 1 AppShell/token/OIDC/URL Scope/OpenAPI generated contract；后续阶段只能扩展，不得创建第二套认证、路由、DTO 或视觉系统。

## 前后端纵向切片

每个阶段都必须同时交付以下链路，禁止先建完所有后端再补前端：

```text
Database / Domain
  -> durable repository and production assembly
  -> OpenAPI / authorization / audit
  -> generated TypeScript contract
  -> high-fidelity operator page and states
  -> security, accessibility, recovery, E2E
  -> signed phase gate
```

前端共同基线：

- 唯一工程 `web/`；Node 24、pnpm 10、React 19.2.7、TypeScript 7.0.2。
- 唯一公共契约 `api/openapi/control-plane-v1.yaml`，唯一生成文件 `web/src/shared/api/schema.d.ts`。
- Keycloak Authorization Code + PKCE、`login-required`、Token 仅内存，请求前刷新，生产缺配置 fail closed。
- URL 保存 Scope、筛选、排序、分页、Tab 和选中项；TanStack Query 保存服务端状态，不引入 Redux。
- 权限仅消费 API `effective_actions`；浏览器不通过角色名推断。
- 视觉为轻量、密集、克制的企业控制台，不使用聊天壳、AI 头像、霓虹、光晕、渐变、玻璃或装饰性 Bento。
- WCAG 2.2 AA、键盘、可见焦点、非颜色状态、reduced motion、44px 目标均进入 Playwright/axe 门。

## 生产闭环验收追踪

| 链路节点 | 实施入口 | 阻断证明 |
|---|---|---|
| 事件/告警/批准定时 | Phase 4 policy/scheduler | 无发布策略、预算或资产资格即不创建调查 |
| 只读调查与 Evidence | Phase 3/5 typed runners，Phase 4 Grant | Scope/Runtime/Grant/credential 任一漂移即停止 |
| Incident/Evidence/Audit 上游工作台 | Phase 7 Incident/Audit pack | Scope、分类或审计链异常关闭生产操作且不泄露原始事实 |
| READ baseline + Action successor | Phase 6 handoff + Phase 7 `production_action_platform_revisions` | 任一摘要、live READ admission 或 accepted Action manifest 不匹配即关闭 queue/claim/admission |
| 不可变 ActionPlan | Phase 7 catalog/plan | 创建只走 `/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}/action-plans`；Principal + URL Scope 构造 HandoffRequest，Loader 前无 Proposal 预读；同一 serializable tx 内重载/重算/恒时比较/`CreateInTx`，任意 Scope、参数、目标、版本或 hash 漂移整笔回滚并使审批失效 |
| 策略、reauth、审批 | Phase 7 authorization/approval | 自批、过期、职责冲突、政策变化均拒绝 |
| 短期 WRITE credential | Phase 7 issuer/Runner | READ/WRITE issuer、Realm、队列、Attempt 严格隔离 |
| 类型化执行 | Phase 7 fixed adapters | 无任意 shell/SQL/endpoint/payload；lease/fencing/幂等 |
| 独立验证 | Phase 7 verification | executor 自报不能成功；必须由独立 READ facts 验证 |
| 不确定结果 | Phase 7 reconciliation/rollback | 不盲重试；stop/revoke/reconcile/safe rollback/human escalation |
| 发布与持续运营 | Phase 8 release waves | SLO、安全、DR、审计、credential cleanup 任一未知即 Hold |

## ADR 唯一编号

| ADR | 创建阶段 |
|---|---|
| `0001` Operational Asset Catalog Overlay | Phase 1 |
| `0002` Connection Compilation and Publication | Phase 2 |
| `0003` Victoria Ecosystem Read Boundary | Phase 3 |
| `0004` Investigation Grants and Live Kill Switches | Phase 4 |
| `0005` Remote Diagnostic Boundary | Phase 5 |
| `0006` PostgreSQL Named Read Diagnostics | Phase 5 |
| `0007` READ/WRITE Credential Isolation | Phase 5 |
| `0008` Evidence and DLP | Phase 5 |
| `0009` Production Read Platform | Phase 6 |
| `0010` Governed Production Action Gates | Phase 7 |
| `0011` Verification, Reconciliation, and Rollback | Phase 7 |
| `0012` Production Release Governance | Phase 8 |

## 完整性规则

- 任何一行若改变实现归属，必须同时更新规范、总计划、两个相关阶段索引和本矩阵。
- 阶段通过只表示它的出口接口可被下一阶段消费；Phase 1–6 的只读能力不是项目最终完成。
- 只有 Phase 8 的独立签名 `PRODUCTION_CLOSED_LOOP_ACCEPTED` 决策可宣称完整生产落地。
- 未通过单独门禁的 Provider、Capability、Action 或资产集合必须在状态/API/UI 中明确保持关闭。
