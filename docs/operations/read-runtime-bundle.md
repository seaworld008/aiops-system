# READ Runtime Bundle 与关闭态 Admission

日期：2026-07-11
阶段：M5C2-4a / M5C2-4c0 / M5C2-4c1a（不可变运行时、heartbeat 重授权与原子装配快照；READ claims 关闭）

## 目的与硬边界

M5C2-4a 先消除两个不能留到 live assembly 才处理的信任缺口：

1. 旧的 `ClaimsEnabled=false` 只拒绝新 Claim，不能阻止升级前已经取得 lease 的
   Start、Heartbeat 或 Complete；
2. connector、target、egress policy 与 executor 虽然各自不可变，但此前没有一个对象证明
   它们属于同一份完整启动快照。

本阶段因此新增单一、不可复制的关闭态 READ Admission，以及不可变 `read-runtime-bundle.v1`。
Control Plane 只能构造关闭态 Admission；没有公开 open 构造器，也没有环境变量或配置值可以
开启 READ claim。关闭态在开始 READ task mutation 事务或调用任何 authorizer 之前拒绝 Claim、
Start、Heartbeat 和 Complete，只保留 GO 前 Release，使旧 lease 也不能借由安装真实 callback
继续推进。mTLS listener 外层仍会访问 PostgreSQL 重新验证 Runner registration、证书与 scope；
Admission 不绕过这项每请求身份复验。

本阶段还提供独立 `internal/readrunnerclient`。它只包含 READ pool 的 mTLS transport 与 READ Task
操作，不导入 WRITE action、execution、credential、revocation、隔离执行器或 mutation adapter。
该客户端尚未由 `cmd/read-runner` 使用；Worker、Outbox dispatcher、Temporal runtime v2 和真实
Bearer provider 也仍未装配。因此 M5C2-4a 不是开放 claim 的 Go/No-Go 证据。

M5C2-4c0 进一步把 heartbeat 改为强制 server-owned authorizer：Task、Attempt 与 Investigation
保持锁定时，对每个合法 next sequence 和 same-sequence replay 重验完整 Bundle。它只补齐安全
续租边界，不新增配置、迁移、open Admission、Worker/Runner 装配或 claim 开关。

M5C2-4c1a 新增 `internal/readassembly.Snapshot`，把 Plan、同一 Connector 实例、Target、Egress 与
固定 Executor Profile 作为一个经过部署摘要钉住的语义快照发布。Snapshot 不导出 Planner、
ScopeAuthority、Registry 或 Bundle 原始 getter；Control Plane/Worker 只能使用窄的 plan resolve、
task/runtime binding、start/heartbeat/completion authorizer 门面，以及直接构造 Runtime v2/READ Runner
Activities 的高层工厂，不能取得私有组件后把不同快照重新混装。

## Egress manifest 与 registry

egress 文件顶层 schema 固定为 `read-egress-policy-registry.v1`：

```json
{
  "schema_version": "read-egress-policy-registry.v1",
  "policies": [
    {
      "scope": {
        "tenant_id": "10000000-0000-4000-8000-000000000001",
        "workspace_id": "20000000-0000-4000-8000-000000000002",
        "environment_id": "30000000-0000-4000-8000-000000000003"
      },
      "policy_ref": "由 BuildEgressPolicyRef 生成的完整内容地址",
      "hostname": "metrics.staging.internal",
      "port": 8443,
      "allowed_prefixes": ["10.42.9.0/24"]
    }
  ]
}
```

文件继续通过 `securemanifest` 的 owner-only 稳定快照门禁。Registry 深拷贝每个定义，拒绝重复
精确键与内容地址漂移，按 scope 与 policy ref 排序后生成 JCS/SHA-256 摘要。摘要条目包含 policy
digest；policy digest 已绑定 hostname、port、CIDR、DNS/literal-dial 与 hard-deny profile，因此
registry 摘要不会因省略 URL 或 Secret 而失去完整性。Registry 没有 reload、fallback 或 mutation
方法，值复制和 JSON 反序列化都不能获得有效能力。

## `read-runtime-bundle.v1`

Bundle 一次性接收且共同拥有以下 Ready 对象：

- immutable connector registry；
- immutable target registry；
- immutable egress registry；
- 二进制固定的 executor profile；
- 由同一组对象构造的 runtime Binder 与 fixed HTTP Executor。

构造期间会遍历 connector 的脱敏 runtime dependency 视图，并逐项证明：

- connector 的 exact Tenant/Workspace/Environment/Service、kind、operation 与完整内容地址有效；
- exact target 存在，scope/kind/TargetRef 与 target digest 一致；
- target 引用的 exact egress policy 存在，scope、policy ref、hostname 与 port 完全一致；
- executor profile 明确支持该 kind/operation。

任一缺失、交叉 manifest 漂移、partial dependency、copied capability 或 digest 不一致都会使整个
Bundle 构造失败，不会发布部分对象。为支持 expand-first 轮换，manifest 可以暂时包含尚未被当前
connector 引用的额外新 target/policy；每个当前 connector 的依赖则必须完整。

Bundle digest 使用 JCS/SHA-256 覆盖：

```text
read-runtime-bundle.v1
  connector_registry_digest
  target_registry_digest
  egress_registry_digest
  executor_profile_digest
```

`AuthorizeStart`、`AuthorizeHeartbeat` 与 `AuthorizeCompletion` 不只调用 connector validator。三者都会先用 Bundle 中的
exact connector/target/policy/profile 重建三个 component digest 和 aggregate RuntimeDigest，并比较
持久 Descriptor 的 Plan RegistryDigest 与全部 RuntimeBinding；随后才执行 typed start/evidence
admission。每个合法 next sequence 和相同 sequence replay 都必须重跑 `AuthorizeHeartbeat`；对这两种
合法序号形态，漂移或 panic 会使 Gateway 在锁内终止有效 attempt，不能续租；过期 lease 仍是 stale，
跳号仍是 conflict。Runner 侧 `Prepare` 也只能由 Bundle 内部解析 execution、target 与 policy，并返回绑定
当前 Bundle 实例和 Bundle digest 的不可复制、一次性 capability；`Execute` 不再接受裸
`readexecutor.Prepared`，因此另一套自洽 runtime 图也不能交换执行材料。调用方不能提交 URL、
TargetRef、policy、query 或摘要。

## 原子装配 Snapshot

`readassembly.LoadFiles` 要求四个 owner-only、clean absolute 且彼此不同的文件路径：Connector、
Investigation Plan、Target 与 Egress。调用方还必须提供完整 `read-assembly-snapshot.v1` 预期摘要：

```text
plan_manifest_digest
connector_registry_digest
target_registry_digest
egress_registry_digest
executor_profile_digest
bundle_digest
```

预期摘要缺失、非规范、内部 Bundle 摘要不自洽或与任一已加载组件不符时，进程启动失败；不存在
“摘要为空则接受当前文件”、inline fallback、reload 或 global current。Plan 与 Bundle 必须共享同一
Connector 实例，ScopeAuthority 只能在 loader 内创建。所有局部组件、依赖图及摘要验证完成后才发布
sealed/self Snapshot；任一失败或 panic 都返回 nil 和固定低敏错误，只有 caller context 的取消/超时
保留可分类语义。这里仅接受精确的 Go canonical `context.Canceled` / `context.DeadlineExceeded`；包装、
自定义或 panic context 全部折叠，不能把路径或 Secret 文本带出。最终 Summary 从验证成功的实际
Planner/Bundle 重新生成并复制字符串，不持有调用方 Expected digest 的 backing storage。

`Bind` 与三类 Runner authorizer 除验证 RuntimeBinding 外，还强制 PlanBinding 的 Manifest/Registry
摘要等于本 Snapshot，阻止另一套自洽 Plan 复用相同 runtime 图。Snapshot 的两个 Activities 工厂只把
私有 authority/planner 或 Bundle 直接交给既有 sealed production constructor；复制、零值、依赖缺失或
namespace 非法都拒绝，API 仍不提供 Prepare/Execute/registry 原始能力。READ Runner Activity 还会在
任何 Temporal heartbeat 或 Gateway Claim 前常量时间核对 Snapshot 的 Plan Manifest/Connector Registry；
production runtime 在 `Bundle.Prepare` 前再对 lease Descriptor 重复核对。因此即使 Runner task queue 的
路由被绕过，旧 Plan 或外部 Plan 的任务也不能进入 Claim/Prepare/Execute。正常路由使用 v2 Runner queue：
Environment 加 Plan/Registry/Bundle 的 domain-separated deployment SHA-256；相同 Bundle 的两代 Plan
因此不会竞争同一队列并随机消耗单次 Activity attempt。

这里的“原子”是经过完整预期摘要钉住后的语义原子发布，不是跨多个文件的 wall-clock 文件系统
事务。每个文件（包括 Target 引用的 CA bundle）仍由 secure manifest loader 独立取得稳定快照；部署
更新途中若读到混合版本，要么所有摘要完全等价，要么拒绝启动。生产 rollout 仍必须使用不可变版本
目录与新进程，禁止热替换。

Snapshot Ready 只证明本地只读图完整，不能作为 READ Admission、Outbox dispatcher 或生产写的
开启信号。本子阶段不新增配置、迁移、`cmd/*` 装配、Bearer provider 或 claim 开关。

## 独立 READ Runner client

客户端固定 TLS 1.3/HTTP/1.1、显式 ServerName 与专属根，禁止系统根、代理、redirect、HTTP/2、
`InsecureSkipVerify` 和请求体身份覆盖；客户端证书必须恰好包含一个
`spiffe://<trust-domain>/runner/read/<instance>` URI SAN 以及唯一 ClientAuth EKU。

Claim 必须同时得到调度器持有的 `ExpectedTask`：安全的 Tenant/Workspace/Environment/Service、
Incident/Investigation/Task ID、position 和完整 PlanBinding。客户端把 Gateway v2 响应与这些事实
组合为 Descriptor，并重新运行 Descriptor/RuntimeDigest 校验；scope 或摘要被替换时不会接受 lease。

原始 43 字符 bearer 只存在于不可复制、可销毁的私有 Lease state：

- 不提供 token/Fence accessor；
- Start 只能由同一 Client 使用同一 Lease 发起；
- 成功 Start 返回没有公开构造器的 `StartCapability`，绑定同一 lease state、task、epoch 与 scope revision；
- Heartbeat sequence 由客户端单调维护，`TERMINATE` 后 capability 失效；
- Release 与 Complete 在客户端内部生成 Authorization 与 fenced 请求，日志、JSON、错误和结果均不含 bearer。

响应必须满足 `Cache-Control: no-store`、`nosniff`、精确 Content-Type、TLS/HTTP 边界和 64/256 KiB
预算；JSON 拒绝未知、重复、大小写别名和尾随文档。RFC 9457 的 title/detail 仅用于有界验证后即
丢弃，客户端只保留低敏 type/status/code/instance；调用方 context value 与 `httptrace` 也会被剥离，
不能观察 Authorization。Claim、Start 和 CONTINUE heartbeat 还必须保有至少 20 秒的本地 lease
窗口，避免收到成功响应时已经来不及续租。客户端使用 self/seal 拒绝零值与按值复制；新 Claim 还要求
客户端证书至少覆盖一次最坏 Gateway 往返、最小可用 lease 窗口和时钟偏差。该 Claim 预算不会错误
阻断已经领取且仍处于证书/lease 有效期内的 Start、Heartbeat、Release 或 Complete。

## 部署与回滚

M5C2-4a 没有迁移、配置、Temporal 注册或 live READ Runner 装配。部署后 Control Plane 仍使用
关闭态 Admission 与 disabled callbacks；未 ACK Outbox 不移动，READ Task 不会被新领或由旧 lease
推进。回滚二进制即可，不需要数据回填。

M5C2-4b 已安装尚未进程装配的 Temporal runtime v2、结果恢复注册和真实 READ Activity。后续 C2-4c
必须在同一个 assembly factory 中加载 connector、target、egress、plan 与 Bundle，核对
Worker/Gateway/READ Runner 的相同 Bundle digest，安装 Outbox supervisor 并完成本地
Signal→Evidence E2E。即使这些代码完成，企业
PKI、Bearer provider、NetworkPolicy/egress enforcement、源侧 DLP、Temporal replay 与无混版部署
证据缺一项时，生产配置仍只能使用关闭态 Admission。

本阶段不改变 `AIOPS_WRITE_EXECUTION_MODE=disabled|non-production`，不新增 production 值，也不
连接 ActionPlan、审批或 mutation adapter；生产写继续不存在可配置启用路径。
