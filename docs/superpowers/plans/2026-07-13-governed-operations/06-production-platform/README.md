# Production Platform and Read Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 Phase 1–5 已验收的资产、连接、Runtime、Grant、主动策略、VictoriaMetrics、Host 与 PostgreSQL 固定只读能力装配为真实高可用生产平台，经过 Preview、非生产 READ_ONLY、生产 SHADOW、受监督生产 READ_ONLY 的不可跳级验证，形成唯一生产只读 Go/No-Go 决策。

**Architecture:** PostgreSQL 是授权、rollout、gate evidence 与 decision 的事实源；Temporal 只负责编排 ID/摘要；Keycloak 负责人的 OIDC 身份；Vault/PKI 通过 Kubernetes workload identity 提供短期服务证书与 READ 凭据；独立 Control Plane、Control Worker、Outbox、Scheduler、Discovery Worker、Gateway、Validation Runner、READ Runner 多副本运行。AWX capability 另消费 Phase 5 已交付的 governed AWX image、HA EnrollmentCleanupBroker/L7 gateway 和 host-local attestor，并以同一 platform revision 锁定其内容摘要。所有组件以内容寻址 platform revision 和 Helm/image lock 部署，Gateway 在四边界继续复验 Grant/Runtime/Realm/Kill Switch；生产写链在代码、配置、chart、网络、身份、凭据和 API 六层关闭。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Temporal Go SDK 1.46.0、Temporal Service、Keycloak Server 26.6.3/keycloak-js 26.2.4、HashiCorp Vault Kubernetes Auth/PKI/Transit、Kubernetes 1.36.2、Helm 3、OpenAPI 3.1、OpenTelemetry/Prometheus/Alertmanager/Grafana、S3-compatible immutable evidence/backup store、Node.js 24、pnpm 10.34.0、React 19.2.7、TypeScript 5.9.3、Vite 8.1.4、Playwright 1.61.1、axe-core 4.12.1、k6、RFC 8785 JCS/SHA-256。

## Global Constraints

- migration 固定为 `000020_production_platform`；不得改写 `000015..000019` 历史 migration。
- 本阶段只消费 Phase 1–5 已通过 gate 的公开接口；任何前序状态未验收、缺表、缺 profile 或摘要不匹配都阻止启动/rollout。
- Production constructor 缺 PostgreSQL、Temporal、Keycloak、Vault/PKI、audit sink、evidence store、Gateway、Runner Realm 或 telemetry 任一必需依赖即启动失败；不存在 memory/fake/loopback/MSW 降级。
- PostgreSQL 是领域事实源；Temporal History、Outbox、浏览器和 metric backend 都不能替代授权、lease、fence、decision 或 audit 事实。
- 核心进程固定为 Control Plane、Control Worker、Outbox Dispatcher、Scheduler、Discovery Worker、Runner Gateway、Validation Runner、READ Runner；职责和 ServiceAccount 分离。AWX-enabled deployment 还必须把两个 EnrollmentCleanupBroker 与 purpose-specific L7 gateway 作为隔离的外部 integration services 运行，不能并入核心进程或复用其身份。
- 多副本行为必须依赖 PostgreSQL/Temporal 的 durable lease、fencing、idempotency 和任务历史；不得依赖进程内 leader、sticky session 或本地磁盘状态。
- SLO 目标为月度 99.9%；PostgreSQL 事实与审计 RPO `<=5m`，清洁环境全路径 RTO `<=30m`，且由真实演练计时证明。
- Preview → nonproduction READ_ONLY → production SHADOW → supervised production READ_ONLY 顺序不可跳过；每步保存 policy、Asset Snapshot、Grant、Runtime、credential cleanup、Evidence、Receipt、Audit 摘要或显式 `NOT_APPLICABLE` 证明。
- SHADOW 不创建可 Claim Task、不签发 Credential、不解析私有 Target、不发送目标网络请求；READ_ONLY 仍不能执行任何写操作。
- 本阶段最终 decision 只允许 `NO_GO`、`CONTINUE_SHADOW`、`APPROVE_PRODUCTION_READ_ONLY`；批准只是 Phase 7 输入，不是项目完成。
- `WRITE` claim、WRITE credential issuer/revoker、WRITE Runner、Action availability、生产 mutation route 和对应 NetworkPolicy 全部关闭；不得通过配置开关、管理员角色或手工数据库修改绕过。
- 模型不是 Principal，不签发/扩展 Grant；浏览器、模型、事件、Temporal、Task 与 Runner payload 都不能覆盖 endpoint、Target、Realm、Credential、query、command、SQL、budget 或 tenant。
- Secret、Token、PEM、DSN、Vault URL/path、内部 endpoint、原始上游错误、query/SQL/command、Evidence 正文不得进入公共 API、日志、Trace、metric label、Temporal History 或审计详情。
- 人员权限由服务端 `effective_actions` 和最近 OIDC 认证决定；前端不按角色名推断，token 仅存内存，缺 Keycloak production 配置 fail closed。
- 所有组件默认拒绝网络，使用独立 ServiceAccount、Vault role、PKI role、Runner Realm、NetworkPolicy 和 Pod Security；身份/证书/Scope revision 漂移实时终止。
- 基础 Helm chart `deploy/helm/aiops/` 由 Phase 6 拥有：Chart/values/schema/helpers、全部只读平台 Deployment/Service/PDB/HPA/Config/基础 NetworkPolicy。本阶段绝不部署 WRITE Runner/Action worker；Phase 7 只增量加入写组件，Phase 8 再整体 harden。
- 前端保持低 AI 感、高密度企业控制台：深海军蓝导航、白/浅灰内容面、克制蓝色动作、4–6px 圆角、1px 边框；禁止聊天壳、AI 头像、霓虹、发光、渐变、玻璃拟态和装饰性 bento。
- 唯一 OpenAPI 为 `api/openapi/control-plane-v1.yaml`，唯一生成类型为 `web/src/shared/api/schema.d.ts`；生产 build 不包含 MSW。
- 新增行为严格 TDD；每个 Task 先确认测试失败，再实现最小生产代码、验证通过并独立 commit。

## Fixed Execution Order

| Order | Task pack | Primary output | Depends on |
|---:|---|---|---|
| 1 | [`01-production-assembly.md`](./01-production-assembly.md) | `000020`、production constructors、八类进程、基础 Helm chart、可复用真实依赖测试栈 | Phases 1–5 accepted |
| 2 | [`02-ha-slo-observability.md`](./02-ha-slo-observability.md) | HA/fencing/drain、99.9 SLI/SLO、dashboard/alerts、load/chaos | Pack 01 |
| 3 | [`03-security-network-identity.md`](./03-security-network-identity.md) | default-deny 网络、Realm、Vault PKI workload identity、Keycloak、DLP/write closure | Packs 01–02 |
| 4 | [`04-backup-recovery-dr.md`](./04-backup-recovery-dr.md) | 加密备份、PITR、clean-room restore、RPO/RTO、灾备/fencing | Packs 01–03 |
| 5 | [`05-shadow-readonly-rollout.md`](./05-shadow-readonly-rollout.md) | 四阶段 gate、API、生产就绪/Realm/SLO/Shadow/decision UI | Packs 01–04 |
| 6 | [`06-e2e-operations-docs.md`](./06-e2e-operations-docs.md) | 真实全栈 E2E、故障/安全/恢复演练、ADR 0009、CI 与决策证据 | Packs 01–05 |

每个 pack 内按 Task 顺序执行。只有文件集合无重叠且前置 interface 已冻结时才可并行；migration、production dependency graph、OpenAPI/generated type、Helm values schema 和 final decision 必须统一复核。

## Consumed Phase 1–5 Contracts

| Phase | Required accepted output | Phase 6 use |
|---|---|---|
| 1 Assets | scoped Asset/Source/Relationship、ACTIVE+EXACT、audit/outbox | rollout scope、snapshot eligibility、source health |
| 2 Connections | immutable Connection/Target/Capability/Runtime、Validation Realm | production dependency closure、validation runner |
| 3 Victoria | 21-resource discovery、18 typed read capabilities、N/N+1 profile | real metrics/logs/traces read path |
| 4 Grants | Asset Snapshot、Grant、six-level Kill Switch、Policy/Run、Gateway four-boundary Gate、Temporal starter | admission、shadow/read-only orchestration |
| 5 Diagnostics | Host/AWX/PostgreSQL fixed contracts、READ issuer/revoker、cleanup、Receipt/Evidence | real host/database read and cleanup proof |

Every production task pins this minimum tuple：Scope/Asset revisions；Connection/Target/Capability/Runtime digests；Policy/Asset Snapshot/Grant/Kill Switch revisions；Runner Realm/Scope/workload identity；Platform/Rollout revisions；Task/Attempt/fencing epoch；credential cleanup state；Evidence/Receipt/Audit chain digests。

Missing、revoked、drifted、stale、uncertain or cross-Scope members stop admission/execution. Caches may hold content-addressed immutable objects only；live Kill Switch、identity、credential cleanup and decision state are re-read at required boundaries.

## `000020` Ownership

The migration creates exactly seven scoped relations:

| Table | Responsibility | Explicitly never stores |
|---|---|---|
| `production_platform_revisions` | immutable dependency/config/image/chart closure | URL、DSN、PEM、credential、raw config |
| `production_platform_components` | component replicas/image/config/identity/Realm/PDB/HPA facts | environment、args、secret mounts/content |
| `production_read_rollout_revisions` | four-stage predecessor-bound rollout | selector body、Target、query、credential |
| `production_rollout_gate_evidence` | typed PASS/FAIL/INCONCLUSIVE evidence digest | raw logs、Evidence body、error text |
| `production_readiness_decisions` | final allowed decision and evidence-set digest | approval token、OIDC claims、free-form reason |
| `production_backup_manifests` | encrypted backup/PITR coverage and safe manifest digest | encryption key、repository credential、data bytes |
| `production_recovery_exercises` | backup/restore/DR/dependency/security drill timing/result | command output、secret、internal endpoint |

All business identities and FKs include `tenant_id/workspace_id/environment_id`. Published/applied revisions, evidence, decisions, backup manifests and exercises are append-only. Down migration refuses while any Phase 6 row or active production-read admission exists.

## Production Component Topology

| Component | Minimum replicas | Durable coordination | External dependencies | Network zone |
|---|---:|---|---|---|
| Control Plane | 3 | stateless + PostgreSQL idempotency | PostgreSQL, Keycloak, audit/evidence | `CONTROL_API` |
| Control Worker | 3 | Temporal task queues/versioning | Temporal, PostgreSQL, audit | `CONTROL_WORKER` |
| Outbox Dispatcher | 2 | PostgreSQL SKIP LOCKED lease/fence | PostgreSQL, Temporal | `CONTROL_OUTBOX` |
| Scheduler | 2 | Temporal Schedule + DB revision | Temporal, PostgreSQL | `CONTROL_SCHEDULER` |
| Discovery Worker | 2 | PostgreSQL source-run lease/fence + durable cursor | PostgreSQL, exact published source adapters | `DISCOVERY_*` |
| Runner Gateway | 3 | PostgreSQL task/Grant/fence transaction | PostgreSQL, Vault/PKI, audit/evidence | `RUNNER_GATEWAY` |
| Validation Runner | 2 per Realm | Gateway mTLS claim/fence | Gateway, validated target only | `VALIDATION` |
| READ Runner | 2 per Realm/family | Gateway mTLS claim/fence | Gateway, exact Target only | `READ_*` |
| Enrollment control services | Broker 2 + L7 gateway 2 | Vault KV version/fence + Raft quorum | Vault 2.0.3 KV/Transit、exact AWX self-PAT/revoke paths | `AWX_ENROLLMENT_CONTROL` |

Every Deployment uses zone and hostname topology spread, PDB, rolling surge, readiness gate, graceful drain and bounded termination. No ingress reaches workers/runners. Browser reaches only Control Plane; Runner reaches only Gateway and exact target egress; Gateway does not accept human bearer tokens on Runner routes.

## Dependency Failure Contract

| Dependency unavailable | New admission | In-flight behavior | Required evidence |
|---|---|---|---|
| PostgreSQL | closed | cancel at next durable boundary | readiness false, no local fallback |
| Temporal | no new workflow/schedule | DB facts remain safe; retry after recovery | namespace/task-queue health, no duplicate start |
| Keycloak | human API closed | authenticated Runner path may finish existing grant | issuer/JWKS alarm, no cached-user bypass |
| Vault/PKI | credential/cert admission closed | existing short lease only until expiry; cleanup still retried | cleanup state and certificate expiry |
| Evidence store | new evidence-producing task closed | no successful completion without artifact | zero orphan receipt |
| Audit sink/outbox backlog | production admission closed at threshold | persist local DB audit/outbox, no loss | backlog age/count |
| Metrics backend | execution may continue safely | rollout approval frozen | missing SLO evidence is INCONCLUSIVE |
| Gateway/Runner | claim closed/retry fenced | expired RUNNING becomes UNCERTAIN, cleanup required | takeover/fence receipt |
| Governed AWX/Broker/L7/host attestor | affected AWX enrollment/diagnostic closed | existing attempts converge only through signed cleanup/manual containment | image/route、live-quorum、Transit/keyring、attestor compatibility evidence |

Unknown dependency state is failure, never healthy-by-timeout.

## SLO and Error Budget

The fixed service objective is 99.9% over a rolling 30-day window for authorized Control API and production READ admission/runner boundaries. Monthly error budget is 0.1% (about 43m50s in 30.44 days). Security denials、caller errors、upstream target failures and Kill Switch closures are reported separately and cannot be relabeled as platform success or hidden from reliability review.

| SLI | Objective |
|---|---|
| authorized Control API availability | `>=99.9%` |
| eligible READ Claim/Start/Heartbeat/Complete availability | `>=99.9%` |
| accepted event/schedule to durable run p95 | `<=30s` |
| Gateway admitted request p95 excluding upstream | `<=500ms` |
| credential cleanup terminal | 99% `<=60s`, 100% `<=5m` or admission closes |
| audit/outbox durable publish p99 | `<=60s` |
| Shadow target/credential/task side effects | exactly `0` |
| production WRITE claim/action/credential availability | exactly `0` |
| PostgreSQL/audit recovery point | `<=5m` |
| clean-room full service recovery | `<=30m` |

Fast-burn alerts use 14.4×/1h and 6×/6h windows；either freezes rollout, both pages on-call. A missing or INCONCLUSIVE SLI cannot approve production read.

## Fixed Rollout State Machine

```text
PREVIEW
  -> NONPRODUCTION_READ_ONLY
  -> PRODUCTION_SHADOW
  -> SUPERVISED_PRODUCTION_READ_ONLY
  -> NO_GO | CONTINUE_SHADOW | APPROVE_PRODUCTION_READ_ONLY
```

Transitions require predecessor `ACCEPTED`, identical or explicitly superseding Platform/Policy/Runtime/Kill Switch closure, complete gate evidence set and recent authorized human decision. `NO_GO` closes production READ admission. `CONTINUE_SHADOW` creates a new Shadow revision/soak window. `APPROVE_PRODUCTION_READ_ONLY` preserves read-only admission and produces Phase 7 input；it cannot make any Action AVAILABLE.

Minimum evidence：Preview 记录精确选入/排除资产及 capability/runtime/Realm/write-closure digest；Nonproduction READ_ONLY 至少 24h、100 次成功代表性运行、覆盖每个 provider family、零越权且 cleanup terminal；Production SHADOW 至少 72h、跨三个繁忙窗口 500 次评估、零 Task/credential/Target request 且预算/SLO 合规；Supervised production READ_ONLY 至少 24h、50 次覆盖 Victoria/Host/PostgreSQL 的人工观察运行、零安全/写入/cleanup breach 且 error budget 绿色。计数不能替代 elapsed soak 或安全门。

## Frontend Information Architecture

Stable routes introduced by Phase 6:

- `/platform/readiness`: safety banner, dependency matrix, stage, gate summary and next allowed action.
- `/platform/dependencies`: PostgreSQL/Temporal/Keycloak/Vault/PKI/audit/evidence/Gateway/Runner status and history.
- `/platform/realms`: Validation/READ Realm identity, capacity, certificate/NetworkPolicy status；no private policy/endpoint.
- `/platform/runtime`: component/image/chart/runtime publication closure and rolling status.
- `/platform/slo`: 30-day SLI, budget burn, alerts, recovery objectives and evidence freshness.
- `/platform/rollouts/$rolloutId`: Preview/Shadow/READ_ONLY timeline, immutable evidence chain and decision panel；`$rolloutId` is the project's TanStack parameter syntax.

The app shell keeps a permanent “生产写：关闭” safety indicator. Actions come only from `effective_actions`; decision requires recent authentication and typed confirmation. Public projections never include endpoint/tenant/credential/query/evidence body. Layout is 12-column at 1440px, 8-column/tablet at 1024px and single-column at 390px with WCAG 2.2 AA, keyboard flow and reduced motion.

## Helm Ownership Across Phases

Phase 6 creates the first complete `deploy/helm/aiops/` chart: metadata、locked values/schema、helpers、ServiceAccounts、ConfigMaps、Control Plane/Worker/Outbox/Scheduler/Discovery Worker/Gateway/Validation Runner/READ Runner Deployments and Services、PDB/HPA、default-deny and exact allow NetworkPolicies. It also imports any earlier Victoria discovery RBAC fragment into validated chart structure. Phase 5-owned `deploy/awx/governed-admission/` remains the sole external enrollment-control deployment bundle；Phase 6 verifies and locks its image/HA/identity/network evidence but does not duplicate it inside the core chart。

Phase 7 may only make WRITE-scoped increments behind separately accepted Action types: extend the closed values/image/identity/PDB/HPA contracts and create the three registered WRITE/Action templates. It must not rename or alter Phase 6 READ workloads, services, recovery, default-deny or READ egress semantics. Phase 8 modifies/hardens the whole chart for release waves, capacity and sustained operations. This ownership sequence is tested by chart file and rendered-resource allowlists.

Exact path ownership is immutable across the three phases:

| Path | Phase 6 | Phase 7 | Phase 8 |
|---|---|---|---|
| `deploy/helm/aiops/Chart.yaml` | Create | Modify version only for accepted WRITE increment | Modify |
| `deploy/helm/aiops/values.yaml` | Create READ baseline | Modify only for accepted WRITE values | Modify/harden |
| `deploy/helm/aiops/values.schema.json` | Create closed READ schema | Modify only with closed WRITE schema branches | Modify/harden |
| `deploy/images.lock` | Create READ image closure | Modify only with accepted WRITE/Action image digests | Verify unchanged for this hardening plan |
| `test/production/images.lock` | Create production-stack image closure | Modify only with the same accepted WRITE/Action image digests | Verify exact match |
| `deploy/helm/aiops/chart_contract_test.go` | Create path/render allowlist | Modify only with registered WRITE additions | Modify/harden |
| `deploy/helm/aiops/action-surface-manifest.yaml` | absent | Create exact accepted WRITE resource/path/identity manifest | Verify immutable binding |
| `deploy/helm/aiops/templates/_helpers.tpl` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/config.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/control-plane.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/control-worker.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/outbox-dispatcher.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/scheduler.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/discovery-worker.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/runner-gateway.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/validation-runner.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/read-runner.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/services.yaml` | Create | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/pdb.yaml` | Create READ budgets | Modify only with WRITE/Action budgets | Modify/harden |
| `deploy/helm/aiops/templates/hpa.yaml` | Create READ scaling | Modify only with WRITE/Action scaling | Modify/harden |
| `deploy/helm/aiops/templates/serviceaccounts.yaml` | Create READ identities | Modify only with accepted WRITE/Action identities | Modify/harden |
| `deploy/helm/aiops/templates/networkpolicy.yaml` | Create READ/default-deny policy | Modify only with manifest-bound WRITE/Action rules；READ/default-deny unchanged | Modify/harden |
| `deploy/helm/aiops/templates/networkpolicy_test.go` | Create manifest-aware network contract | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/recovery-job.yaml` | Create after recovery contract | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/recovery-job_test.go` | Create recovery render/safety contract | unchanged | Modify/harden |
| `deploy/helm/aiops/templates/write-runner-deployment.yaml` | absent | Create | Modify/harden |
| `deploy/helm/aiops/templates/write-runner-networkpolicy.yaml` | absent | Create | Modify/harden |
| `deploy/helm/aiops/templates/action-workers-deployment.yaml` | absent | Create | Modify/harden |

Phase 8 must not introduce alternate workload、deployment、configuration or pluralized policy/PDB/HPA template aliases. New release-only files such as chart documentation、NOTES、PodMonitor and chart test fixtures must be declared `Create`; every path above must be declared `Modify` when changed. All rendered resources and schema validation target Kubernetes `1.36.2`.

## Gate Evidence Registry

Every gate has a stable code, owner, freshness window, typed result and sanitized artifact digest. A stage cannot invent ad-hoc gates or convert `INCONCLUSIVE` to PASS. The rollout revision freezes the required registry version；adding or weakening a gate creates a successor rollout and repeats affected stages.

| Gate code | Required proof | Owner | Maximum freshness |
|---|---|---|---|
| `PLATFORM_REVISION_ACCEPTED` | component/image/chart/config/identity closure accepted | platform owner | rollout lifetime |
| `DEPENDENCY_CLOSURE_HEALTHY` | every mandatory dependency has a successful real probe | platform owner | 5m |
| `PHASE_INPUTS_ACCEPTED` | Phase 1–5 acceptance digests still match | program owner | stage start |
| `SCOPE_REALM_EXACT` | Scope、Realm、ServiceAccount、PKI SAN and policy digest agree | security owner | 5m |
| `NETWORK_DEFAULT_DENY` | rendered and observed default-deny plus exact egress | security owner | deployment revision |
| `OIDC_RECENT_AUTH` | Keycloak issuer/client/auth-time policy verified | identity owner | decision request |
| `WORKLOAD_IDENTITY_VALID` | short certificate chain/SAN/TTL/revocation valid | identity owner | certificate half-life |
| `GRANT_RUNTIME_CURRENT` | Grant、Runtime、Capability and Asset Snapshot remain current | control owner | every boundary |
| `KILL_SWITCH_OPEN_FOR_READ` | six-level live state explicitly permits only READ | control owner | every boundary |
| `UNAUTHORIZED_WRITE_SURFACE_ABSENT` | observed WRITE API/chart/identity/network/credential/claim set exactly equals the accepted Action manifest；the Phase 6 manifest is empty | security owner | build + deployment |
| `SHADOW_ZERO_SIDE_EFFECT` | zero Task、Claim、Credential、Target request and Receipt | rollout owner | complete Shadow window |
| `READ_CREDENTIAL_CLEAN` | every issued READ credential reaches terminal cleanup | credential owner | 60s/5m thresholds |
| `HA_FENCE_PROVEN` | stale owner/epoch rejected during takeover and rolling drain | reliability owner | deployment revision |
| `SLO_BUDGET_HEALTHY` | 30-day objective and multi-window burn remain within policy | SRE owner | 5m |
| `AUDIT_CHAIN_COMPLETE` | expected domain events map one-to-one to immutable audit/outbox | audit owner | stage window |
| `DLP_SCAN_CLEAN` | canaries absent from API/log/trace/metric/history/artifacts | security owner | stage window |
| `BACKUP_RECENT_VALID` | encrypted immutable backup/PITR manifest verified | recovery owner | RPO window |
| `CLEAN_ROOM_RECOVERY_PROVEN` | isolated restore meets RPO/RTO and keeps admission closed | recovery owner | 30d |
| `DEPENDENCY_DRILLS_PASS` | required dependency outage and recovery drills pass | SRE owner | 30d |
| `RUNNER_CRASH_RECOVERED` | crash/takeover/fence/cleanup creates one terminal result | runner owner | deployment revision |
| `STAGE_SOAK_COMPLETE` | server-observed elapsed time, sample count and busy windows meet floor | rollout owner | current stage |
| `HUMAN_SUPERVISION_COMPLETE` | authorized observers acknowledge representative READ outcomes | operations owner | supervised stage |

Evidence rules:

- Result is exactly `PASS`、`FAIL` or `INCONCLUSIVE`; absence is `INCONCLUSIVE`.
- Evidence binds Scope、platform revision、rollout revision、stage、gate code、collector version、observed interval and artifact digest.
- Collectors write through typed repositories；browser and pilot scripts cannot insert or update gate rows.
- Artifact stores retain encrypted detailed evidence；PostgreSQL retains allowlisted summary、counts、timestamps and digest only.
- Recollection appends a new observation and never overwrites history；decision binds the ordered accepted observation set.
- A failed security、write-closure、credential-cleanup or split-brain gate immediately closes production READ admission.
- Stale reliability/recovery/SLO evidence freezes advancement and yields `INCONCLUSIVE`, even when the previous sample passed.
- `NOT_APPLICABLE` is allowed only for a gate whose registry definition permits it and requires a typed reason plus reviewer digest.

Gate use is partitioned rather than treating every observation as a per-request condition:

- `ApprovalGateSet` contains all 22 registry codes and is required only for `APPROVE_PRODUCTION_READ_ONLY`.
- `RuntimeAdmissionGateSet` contains `PLATFORM_REVISION_ACCEPTED`, `DEPENDENCY_CLOSURE_HEALTHY`, `PHASE_INPUTS_ACCEPTED`, `SCOPE_REALM_EXACT`, `NETWORK_DEFAULT_DENY`, `WORKLOAD_IDENTITY_VALID`, `GRANT_RUNTIME_CURRENT`, `KILL_SWITCH_OPEN_FOR_READ`, `UNAUTHORIZED_WRITE_SURFACE_ABSENT`, `READ_CREDENTIAL_CLEAN`, `HA_FENCE_PROVEN`, `SLO_BUDGET_HEALTHY`, `AUDIT_CHAIN_COMPLETE`, `DLP_SCAN_CLEAN`, `BACKUP_RECENT_VALID`, `CLEAN_ROOM_RECOVERY_PROVEN`, `DEPENDENCY_DRILLS_PASS` and `RUNNER_CRASH_RECOVERED`.
- `OIDC_RECENT_AUTH` is evaluated only for a human decision request；it is never cached as a permanent approval and never required for Runner claim/start/complete.
- `SHADOW_ZERO_SIDE_EFFECT`, `STAGE_SOAK_COMPLETE` and `HUMAN_SUPERVISION_COMPLETE` remain immutable rollout-decision evidence after acceptance；they are not queried on every READ attempt.
- `CONTINUE_SHADOW` requires current platform/Scope/network/identity/Kill Switch/write-surface safety gates, an accepted Shadow predecessor and recent authorized human decision, but permits incomplete reliability、soak or recovery evidence to remain non-PASS.
- A failed `UNAUTHORIZED_WRITE_SURFACE_ABSENT`, `SCOPE_REALM_EXACT`, `NETWORK_DEFAULT_DENY`, `WORKLOAD_IDENTITY_VALID`, `KILL_SWITCH_OPEN_FOR_READ` or `DLP_SCAN_CLEAN` safety gate removes `CONTINUE_SHADOW`; only `NO_GO` remains.
- `NO_GO` may be recorded by an authorized recently authenticated actor from any nonterminal rollout state without manufacturing PASS evidence；it atomically closes production READ admission.

## Public Projection and Interaction Contract

The Control Plane exposes purpose-built projections, never database rows or generic JSON documents. `effective_actions` is computed against current subject、Scope、stage、decision、recent-auth and Kill Switch state on every response.

| Page/API projection | Safe fields | Explicitly excluded |
|---|---|---|
| readiness summary | stage、overall result、gate counts、freshness、next action | internal dependency address、free-form error |
| dependency status | dependency kind、health class、last success age、incident code | URL、DSN、namespace credential、raw probe body |
| Realm status | Realm kind、revision digest、replica/capacity class、cert expiry class | CIDR、hostname、target、SAN subject details |
| runtime closure | component、version/image digest、replica readiness、rollout status | environment、args、secret mount/path |
| SLO summary | SLI value、objective、budget remaining、burn class、window | raw label sets、tenant/user/target series |
| rollout stage | predecessor、started/ended time、minimum progress、gate result | selector、query、Target、Evidence body |
| gate observation | code、result、freshness、safe reason、artifact digest | log、trace payload、stack、credential |
| cleanup summary | issued/completed/uncertain counts、oldest age | credential ID/value、backend username |
| recovery summary | exercise type、RPO/RTO、result、manifest digest | bucket、KMS key、snapshot path、restore command output |
| final decision | allowed enum、time、actor digest、evidence-set digest | token、claims、free-form justification |

Interaction rules:

- Route loader first resolves current Scope；scope drift cancels outstanding request and clears cached projections.
- Safety banner, current stage and “生产写：关闭” remain visible on every Phase 6 page and viewport.
- Table sorting/filtering changes URL state；refresh and shared links reproduce the same safe view.
- Failure and `INCONCLUSIVE` states use text/icon/shape in addition to color；no optimistic success before server response.
- Decision drawer lists every blocking gate, requires fresh Keycloak authentication and exact typed confirmation.
- `CONTINUE_SHADOW` is visible only after production Shadow；approval is absent when any required gate is not PASS.
- Destructive-looking controls use verb-object labels and disclose durable effect；there is no generic “Run AI” or chat entry point.
- Live refresh pauses while keyboard focus is inside a table/menu/dialog and announces material changes through an ARIA live region.
- At 390px, gate rows become labeled key/value cards without hiding result/freshness；critical actions remain after evidence details.
- Empty/loading/error/offline/forbidden/stale states are designed and tested separately, never represented by a blank panel.

## Phase 7 Handoff Contract

Phase 6 produces one immutable handoff envelope atomically with the final approval decision. Only a `production_readiness_decisions` row whose decision is `APPROVE_PRODUCTION_READ_ONLY` persists non-null `handoff_id uuid` and canonical `handoff_digest sha256`; `NO_GO` and `CONTINUE_SHADOW` persist both as SQL `NULL`. A composite unique constraint and completed-fact immutability trigger protect the full Scope+rollout+decision+handoff tuple for Phase 7 references. The envelope contains no authority to execute writes；it is evidence that the governed READ substrate is ready to be consumed by the separate Action/WRITE approval phase.

Required handoff fields:

- server-generated handoff UUID and domain-separated canonical handoff digest;
- `read_baseline_digest`, computed from the accepted Phase 1–5 input tuple、Phase 6 platform/rollout/decision tuple、ordered gate evidence set and READ-owned chart/schema/image/identity/network digests;
- accepted Phase 1–5 input digests and Phase 6 platform/rollout/decision revisions;
- Helm chart、values schema、component image and workload identity digests;
- ordered gate observation set and sanitized artifact manifest digest;
- observed 99.9% SLO/error-budget state and capacity envelope;
- latest successful backup/clean-room restore/DR exercise with measured RPO/RTO;
- Realm、NetworkPolicy、PKI、DLP and unauthorized-write-surface-absence proofs;
- stage soak intervals/sample counts and supervised READ coverage;
- open risks、expiry timestamps and revalidation triggers;
- exact decision enum and actor/authentication digests.

Canonicalization uses RFC 8785 JCS with domain prefix `aiops.production-read-handoff.v1`. `handoff_digest` covers `handoff_id`, Scope, `read_baseline_digest` and every field listed above；the detailed immutable envelope is retrieved from the evidence service by `handoff_id` and must recompute to the decision-row digest before Phase 7 can publish a successor. PostgreSQL keeps no secret or raw evidence in the decision row.

Phase 7 must reject the envelope when the decision is not `APPROVE_PRODUCTION_READ_ONLY`, any evidence is expired/superseded, the Phase 6 baseline digest differs, admission is closed, or an undeclared write surface exists before successor publication. Phase 7 adds its own Action types、WRITE grants、credentials、Runners and gates；it cannot reinterpret Phase 6 READ approval as WRITE approval.

The Phase 6 handoff and READ baseline digest remain immutable. A legitimate Phase 7 change publishes a separately content-addressed successor deployment revision that references that baseline and an accepted Action manifest；it does not mutate or invalidate the baseline merely because registered WRITE files exist. Before that successor is accepted, the allowed WRITE manifest is empty. After acceptance, queue、claim、admit、pre-mutation、verification and every new READ admission validate both the Phase 6 baseline and the current Phase 7 successor, while `UNAUTHORIZED_WRITE_SURFACE_ABSENT` rejects any observed surface outside the exact accepted manifest. A changed READ-owned path, unregistered WRITE resource or missing dual-revision binding closes admission；a matching accepted WRITE increment does not.

`PLATFORM_REVISION_ACCEPTED` has two explicit resolver modes. With no successor, the observed whole-chart/schema/image lock must equal the Phase 6 platform revision. With an accepted successor, the observed whole artifacts must equal the successor chart/schema/image/identity/network digests, while the successor's recomputed READ-owned subset must equal the Phase 6 `read_baseline_digest` and handoff. The resolver never compares a legitimate successor's whole-chart digest directly with the older whole-chart digest, and never allows the successor manifest to mask a changed READ-owned byte.

## Final Decision Gate

The decision service accepts only:

```go
const (
    DecisionNoGo                     Decision = "NO_GO"
    DecisionContinueShadow            Decision = "CONTINUE_SHADOW"
    DecisionApproveProductionReadOnly Decision = "APPROVE_PRODUCTION_READ_ONLY"
)
```

Free-form decisions, `GO`, `APPROVE_WRITE`, emergency bypass and direct status updates are invalid. Decision digest binds rollout revision, ordered gate evidence digests, actor subject digest, authentication time, platform revision and previous decision. API/audit display a safe reason code enum, never arbitrary text.

## Program Acceptance Gates

- `000020` real PostgreSQL up/down/up, Scope FK, immutability, predecessor and down guard pass.
- Every production constructor and binary rejects each missing/typed-nil/fake/loopback dependency before readiness.
- Three/multi replica lease/fence/idempotency, rolling drain, dependency failure and Runner crash tests pass without duplicate Task/Evidence/Receipt/Audit.
- Keycloak Server 26.6.3 real login/reauth/logout and browser keycloak-js 26.2.4 in-memory token security pass；Vault workload identity/PKI rotation/revocation/cleanup pass.
- Phase 6 render contains only READ components and an empty Action manifest；the enduring contract is exact ServiceAccount/Realm/NetworkPolicy plus zero WRITE resource outside the current accepted manifest.
- 99.9 SLO/burn alerts, dependency/dashboard signals, sensitive-label scan and audit chain are complete.
- PostgreSQL PITR and clean-room restore prove RPO `<=5m` and RTO `<=30m`; split-brain/failover remains fenced.
- Preview/nonproduction READ_ONLY/production SHADOW/supervised READ_ONLY run in order with immutable evidence and zero write availability.
- Production UI at 1440/1024/390, keyboard, axe and real Keycloak Playwright passes；MSW absent from production bundle.
- Final decision is one of the three allowed values and explicitly states it is Phase 7 input, not the program endpoint.

## Final Program Command

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build ./cmd/...
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/productionplatform/postgres -count=1
pnpm --dir web generate:api:check
pnpm --dir web check
pnpm --dir web test:e2e
helm lint deploy/helm/aiops
./test/production/verify-all.sh
git diff --check
```

Expected: every command exits 0；no skipped security/DR/E2E gate, no generated diff, no pending marker, no fake/memory/loopback/MSW production dependency, and no WRITE deployment/claim/credential/action outside the accepted manifest（empty in Phase 6）.
