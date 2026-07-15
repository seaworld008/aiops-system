# 05 Host 与 PostgreSQL 只读诊断阶段索引

> 状态：规划完成，尚未执行。实现基线固定为 `main@ad50d9f`。

本目录把三种 Connection Provider 的验证/发布、AWX Inventory 增量发现、主机固定探针、AWX 预发布只读模板、PostgreSQL 命名诊断查询、独立 READ 凭据生命周期、公共 API、企业级前端与生产验收拆成八个可独立审查的任务包。执行者必须按固定顺序完成，保留每个 Task 的红灯、最小实现、绿灯与 commit 边界。

## 阶段目标

在不引入终端、远程会话、任意命令或任意 SQL 的前提下，让 Phase 1–4 已治理的 Asset、Connection、Target、Capability、Runtime、Realm、Snapshot、Grant、Budget 和 Evidence 真正落到两类生产只读诊断：

```text
Governed Asset + installed Integration
  → server-owned HOST_PROBE_MTLS | AWX_API | POSTGRESQL draft/revision
  → isolated fixed-protocol Validation Runner
  → typed Target + Capability + immutable Runtime N/N+1
  → per-Provider exact AVAILABLE gate
  → AWX_INVENTORY incremental/full SourceRun when provider is AWX
  → Asset Observation/provenance/soft-stale/restore

Incident / Schedule / Human
  → immutable Asset Snapshot + short InvestigationGrant
  → fixed Host Probe or named PostgreSQL DiagnosticQuery
  → authenticated READ Runner / Gateway
  → bounded typed parameters
  → fixed mTLS probe / AWX template / read-only transaction
  → bounded projection → DLP → Evidence
  → durable credential cleanup
  → immutable diagnostic receipt + audit chain
```

本阶段是 Governed Operations Program 的第五阶段，交付可生产的 Host 与 PostgreSQL 只读路径；它仍不开放生产写。任何后续 WRITE 必须经过独立 ActionEnvelope、策略、最近认证、审批、短期单用途 WRITE 凭据、隔离执行与事后验证。

## 固定执行顺序

| 顺序 | 任务包 | Task | 完成门槛 |
|---:|---|---:|---|
| 1 | [01-host-assets-contracts.md](./01-host-assets-contracts.md) | 1–2 | 000019 八表、Host/AWX/PostgreSQL 契约事实与不可变/回滚保护通过 |
| 2 | [02-provider-publication-runtime.md](./02-provider-publication-runtime.md) | 3–5 | 三 Provider schema/Credential/真实验证、typed Runtime N/N+1、独立 gate 与 AWX 增量发现通过 |
| 3 | [03-provider-api-web-e2e.md](./03-provider-api-web-e2e.md) | 6–8 | OpenAPI/authz、server draft→canonical route、六步三分支向导、真实协议与 AWX Source E2E 通过 |
| 4 | [04-host-probe-awx.md](./04-host-probe-awx.md) | 9–10 | mTLS Host Probe 与 AWX 预发布模板执行、双层命令封锁和 Evidence 验证通过 |
| 5 | [05-postgresql-contracts.md](./05-postgresql-contracts.md) | 11–12 | 六个命名查询、严格参数、SQL 静态拒绝、私有编译和摘要绑定通过 |
| 6 | [06-postgresql-runner-credentials.md](./06-postgresql-runner-credentials.md) | 13–15 | READ issuer/revoker 隔离、PostgreSQL 只读执行、持久 cleanup/recovery 通过 |
| 7 | [07-api-web.md](./07-api-web.md) | 16–18 | 显式诊断权限/OpenAPI/HTTP、固定参数、Evidence/脱敏/cleanup UI 与响应式验收通过 |
| 8 | [08-e2e-operations-docs.md](./08-e2e-operations-docs.md) | 19–21 | 真实依赖集成、负向安全、Playwright/axe、SLO/恢复演练和状态文档通过 |

## 000019 精确所有权

迁移名固定为 `000019_host_postgresql_read_diagnostics`，只允许创建以下八张表：

| 表 | 责任 | 明确不存储 |
|---|---|---|
| `host_probe_contract_revisions` | Host Probe 固定探针、参数 schema、预算、结果 schema 与内容摘要 | command、argv、env、path、script、endpoint、凭据 |
| `awx_read_template_revisions` | 预发布 inventory、job template、limit enum、extra-vars schema 与输出投影 | 自由 inventory/template/limit、任意 extra_vars、AWX token |
| `postgres_diagnostic_query_revisions` | 命名查询、schema version、私有 SQL 模板、参数/结果 schema、预算与摘要 | DSN、用户名、密码、调用方 SQL/timeout |
| `read_credential_leases` | 单 Task/Attempt 的 READ 凭据签发事实、密文 accessor 与状态 | credential value、password、完整 Vault URL/path |
| `read_credential_cleanup_attempts` | 可恢复的吊销 claim、尝试、结果和稳定错误码 | secret、原始上游 body/error |
| `diagnostic_execution_receipts` | probe/query、input hash、计数、字节、截断、DLP、Evidence、cleanup 与审计关联 | 原始命令、SQL、完整结果、内部 endpoint |
| `awx_host_identity_enrollments` | release-authorized template verification、完整 cohort、seal 与 N+1 Runtime 根状态 | Secret、Token、任意命令、公开 Host identity |
| `awx_host_identity_enrollment_attempts` | 每 Host fenced enrollment、Job/attestation 摘要与 cleanup 闭包 | stdout、任意 event/fact、Token/accessor、endpoint |

八表都使用 `(tenant_id, workspace_id, environment_id, ...)` 复合作用域键；所有引用必须绑定 Phase 1–4 已发布事实。AWX/Host 的唯一后继事实源是 [identity enrollment](../../../../contracts/awx-host-identity-enrollment-v1.md)、[governed launch admission](../../../../contracts/awx-governed-launch-admission-v1.md) 与 [host identity attestor](../../../../contracts/host-identity-attestor-v1.md)；迁移不得复制 Connection endpoint、Target 内容、Realm 网络策略、Grant 权限或 Evidence 正文。

## 固定能力矩阵

### Host

| Capability | Provider | 唯一动态输入 | 结果上限 |
|---|---|---|---|
| `HOST_SYSTEM_INFO` | `HOST_PROBE_MTLS` | `{}` | 单个版本化对象 |
| `HOST_CPU_MEMORY_SNAPSHOT` | `HOST_PROBE_MTLS` | `sample_window_seconds` enum | 固定指标集合 |
| `HOST_DISK_USAGE` | `HOST_PROBE_MTLS` | `filesystem_scope` enum | 64 行 |
| `HOST_NETWORK_LISTENERS` | `HOST_PROBE_MTLS` | `address_family` enum | 128 行、地址 DLP |
| `HOST_SYSTEMD_STATUS` | `HOST_PROBE_MTLS` | `unit_id` enum | 单个服务投影 |
| `HOST_WINDOWS_SERVICE_STATUS` | `HOST_PROBE_MTLS` | `service_id` enum | 单个服务投影 |
| `HOST_BOUNDED_LOG_WINDOW` | `HOST_PROBE_MTLS` | `log_source_id`、`lookback_seconds` enum | 200 行/256 KiB/DLP |
| 上述安全子集 | `AWX_API` | 预发布 `inventory_id`、`template_id`、`limit_id` 的服务端映射；调用方仍只传 typed 参数 | 与 capability 相同 |

Host 明确禁止：caller-supplied command、argv、env、path、glob、script、interpreter、stdin；interactive SSH/WinRM、shell、PTY、Agent Forwarding、local/remote/dynamic forwarding、SFTP/SCP、任意文件下载。未来若引入 SSH/WinRM，必须另立 ADR 和独立阶段，不得借本计划扩展。

### Connection Provider 与 AWX Inventory 来源

- `HOST_PROBE_MTLS`、`AWX_API`、`POSTGRESQL` 必须各自完成 Provider 判别 Revision、同 Scope Opaque Credential Reference、真实固定协议 Validation、typed Target/Capability/Runtime 和精确 `AVAILABLE` gate；一个 Provider 的状态不能推断另一个。
- Connection ID、Revision、Operation 与 Runtime 身份由服务端生成；前端首个草稿持久化后立即进入 canonical Revision route，N+1 不覆盖 N，在途运行固定原 Bundle。
- AWX Connection 必须绑定 canonical installed Integration；只有 exact AWX Runtime gate 可用后，同 Integration 的 `AWX_INVENTORY` Source 才可运行。
- AWX Source 使用密封增量/全量 cursor、单调 run fence、逐字段 allow-listed provenance；增量 run 不做缺失判定，成功全量 run 仅 soft-stale，恢复追加事实但等待重新验证激活。
- AWX 429 保持 cursor、持久化 `not_before` 并释放 lease；禁止进程内 busy retry。Source Adapter 只读固定 Inventory/Host API，禁止 job launch、任意 template、extra_vars、command 或 raw host variables。

### PostgreSQL

| Capability / Query ID | 唯一动态输入 | 固定安全语义 |
|---|---|---|
| `POSTGRES_SERVER_HEALTH` / `postgres.server-health.v1` | `{}` | server version family、recovery/read-only 状态、uptime bucket |
| `POSTGRES_CONNECTION_SNAPSHOT` / `postgres.connection-snapshot.v1` | `state` enum | 聚合连接计数，不返回 query/application/client address |
| `POSTGRES_LOCK_SNAPSHOT` / `postgres.lock-snapshot.v1` | `minimum_wait_seconds` enum | 锁类型与等待 bucket，标识符 HMAC/DLP |
| `POSTGRES_REPLICATION_SNAPSHOT` / `postgres.replication-snapshot.v1` | `replication_scope` enum | 聚合状态与 lag bucket，不返回 slot/host secret |
| `POSTGRES_DATABASE_SIZE` / `postgres.database-size.v1` | `database_scope` enum | 当前库或预发布 allowlist，大小 bucket |
| `POSTGRES_SLOW_QUERY_SUMMARY` / `postgres.slow-query-summary.v1` | `minimum_calls`、`top_n` enum | 仅已允许扩展存在时的 queryid 聚合；不返回 query text |

PostgreSQL 明确禁止：任意 SQL、多个 statement、DDL、DML、`COPY`、large object、任意函数、扩展安装/调用、临时对象、`LISTEN/NOTIFY`、`EXPLAIN ANALYZE`、调用方 timeout/search_path/role/database/DSN。每个 Query 使用固定 `BEGIN READ ONLY`、固定 `search_path=pg_catalog`、`statement_timeout`、`lock_timeout`、`idle_in_transaction_session_timeout`、行/字段/字节/时间上限；超限、未知列、DLP 拒绝或清理不确定都 fail closed。

## 授权与凭据不变量

- 单次授权只绑定一个 Asset、一个 Capability、一个 Task、一个 Attempt epoch、一个 Target、一个 Runtime、一个 Realm 和一个 Grant。
- Grant 短期且不可续期；Runner heartbeat 不能延长 Grant、Credential 或 query/probe contract。
- READ issuer、READ revoker、READ Vault role/mount、READ 表和生产装配与 WRITE 完全分离；READ 类型不得实现或适配 `credential.DurableBroker` 的 WRITE 接口。
- Credential 只在 Start 后按需签发并单次交付给受认证 Runner 内存；数据库仅保存加密 accessor 和 HMAC，不保存用户名/密码。
- Complete、Cancel、Timeout、Runner crash、Gateway crash 都必须进入 durable cleanup；只有 `REVOKED` 或 `NO_CREDENTIAL` 才能终结。
- revoke 结果不确定、issuer/revoker 不可用、accessor 解密失败或 cleanup 超 SLO 时，关闭新 Claim、停止受影响运行并进入人工处置；不得假定已吊销。
- Claim、Start、Heartbeat、Complete 继续消费 Phase 4 同事务 GrantGate；Host/PostgreSQL 运行时 authorizer 是附加边界，不能替代 GrantGate。

## 公共与 Runner 边界

浏览器只访问 Control Plane API。公共 DTO 可显示：

- Capability/Query/Probe 的公开 ID、schema version、描述和允许参数枚举；
- 固定 budget 摘要、运行阶段、低基数 failure code；
- row/item/byte count、`truncated`、DLP/redaction 摘要；
- Evidence 安全投影、cleanup state、audit/trace ID；
- 服务端计算且排序去重的 `effective_actions`。

公共 DTO 不显示 endpoint、server name、CA、DSN、database host、credential reference、Vault、Runner identity、AWX URL/token、inventory/template 数字 ID、SQL、command、raw error 或完整结果。Runner 协议只能收到签名且私有的运行时 capsule；任务输入不得包含安全敏感字段。

诊断授权必须显式区分 `CAPABILITY_READ`、`DIAGNOSTIC_READ`、`DIAGNOSTIC_RUN`、`DIAGNOSTIC_CANCEL`、`SENSITIVE_EVIDENCE_READ`。RUN 不推断 READ/CANCEL；own-run 或 published on-call 只是取消/敏感 Evidence 的附加对象关系，不能替代权限。Sensitive Evidence 还要求 5 分钟内 recent auth，所有授权都重新校验 Service Scope 与完整 Scope。

## 前端设计基线

前端继续使用唯一 `web/` 工程；若 Phase 1 执行后该目录尚不存在，应先完成 Phase 1 前端基线，不能另建第二个应用。第五阶段页面固定为 Asset Detail 的“固定诊断”Tab 和可深链的运行抽屉：

1. 左侧为 capability 列表与状态，右侧为固定参数表单和只读预算卡；
2. 发起后展示 `授权 → 排队 → 凭据 → 执行 → DLP → Evidence → Cleanup` 持久阶段轨道；
3. Evidence 用类型化表格/定义列表，不使用日志终端、SQL 编辑器或 JSON dump；
4. DLP 拒绝、截断、预算耗尽、Grant 撤销、Target 漂移、cleanup uncertain 均是独立持久状态；
5. URL 保存 `tab=diagnostics`、`diagnostic_capability` 与 `diagnostic_run`，刷新/后退/分享后恢复；
6. 所有动作只认 `effective_actions`，危险状态不显示运行按钮，不在前端推断角色。

详细页面、组件、密度、交互、响应式和无障碍规范持久化到 `docs/design/frontend/host-postgresql-diagnostics.md`，由第七个和第八个任务包实现与验收。

## 执行规则

1. 从包 01 开始；后一包只消费前一包的 `Produces`。
2. 每个 Task 必须先写失败测试，运行并确认指定失败，再实现最小生产代码、运行通过并提交。
3. 不得跳过真实 PostgreSQL、Vault、Host Probe、AWX fixture 的集成测试而宣称生产就绪。
4. fake、MSW、内存 repository、静态 fixture 只能存在于测试目录或 `*_test.go`；生产启动缺任何依赖必须 fail closed。
5. 所有日志、Trace、Metric label、Temporal payload、audit 和失败响应执行敏感字段扫描；测试要证明秘密未出现。
6. 实现本阶段不会自动打开生产 READ Admission；启用需要最后一个包的 Go/No-Go、清理演练、SLO 和人工批准。
7. 文档中的版本与依赖以 Phase 1–4 锁定值为准；执行前若基线已变化，先做兼容审计，不得静默改契约。

## 完成定义

只有以下条件同时满足才可把第五阶段写为完成：

- 000019 在 PostgreSQL 18.4+ 空库 up/down/up 通过，持久状态 rollback 被 guard 拒绝；
- Host mTLS Probe 与 AWX 只执行预发布读取能力，负向测试证明零 shell/PTY/forwarding/SFTP/自由参数；
- Host/AWX/PostgreSQL Connection 从 server draft 到 canonical N/N+1 Runtime 全链通过，各 Provider gate 独立；
- `AWX_INVENTORY` 增量/全量 Source 通过 cursor、HA fence、field provenance、rate limit、soft-delete/restore 和真实协议 E2E；
- 六个 PostgreSQL Query 通过静态验证、真实只读事务、超时/上限/DLP 和扩展降级测试；
- READ issuer/revoker 与 WRITE 隔离，完成/cancel/timeout/crash 的 cleanup 均可恢复且有演练证据；
- API/OpenAPI 只暴露安全 DTO，浏览器无 terminal/SQL editor/endpoint/credential；
- Playwright 在 1440/1024/390、键盘与 axe 下通过；
- 指标、告警、SLO、备份/恢复、故障注入、值班手册和人工处置流程均落盘；
- `go test ./...`、integration、race、OpenAPI、前端测试、E2E、secret scan 和 `git diff --check` 全绿。
