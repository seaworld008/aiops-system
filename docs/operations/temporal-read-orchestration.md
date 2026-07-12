# Temporal READ investigation orchestration

阶段：M5C2-4b / M5C2-4c1a（版本化只读编排、Plan-bound Runner 路由；尚未进行进程装配，READ claims 关闭）

本阶段把既有 investigation preparation、持久 READ Task、mTLS Gateway、结果恢复和 atomic
runtime Bundle 连接成可 replay 的 Temporal v2 协议，但不修改 `cmd/*`、配置、Outbox dispatcher、
Gateway Admission、迁移或公开 API。Control Plane 仍安装关闭态 Admission，生产代码仍没有打开 READ
claims 的构造器；WRITE claims 与 production write 也继续不存在启用路径。

## 固定协议身份

协议名称和队列均由代码生成，部署配置不能覆盖：

- Workflow：`aiops.investigation.read.v2`；
- preparation Activity：`aiops.investigation.prepare.activity.v2`；
- DB recovery Activity：`aiops.investigation.read-result.recover.activity.v1`；
- Runner Activity：`aiops.investigation.read-task.execute.activity.v1`；
- Workflow Memo：`aiops.investigation.read.identity.v2`；
- control queue：`aiops-investigation-read-v2-<manifest>-<registry>-<bundle>`；
- Runner queue：`aiops-investigation-read-task-v2-<environment UUID>-<deployment SHA-256>`；deployment
  hash 以固定 domain separation 对 manifest、registry、bundle 三摘要计算，队列不暴露原始三摘要。

Workflow ID 必须等于持久 Outbox event ID。Memo 必须恰好包含一个字段，其 `json/plain`
payload 必须与 JCS canonical Workflow input 完全相等。Workflow 拒绝 parent、cron、retry、continue、
search attributes、额外 Memo、非默认 priority、错误 namespace、错误 task queue 和错误 Workflow timeout。

control queue 同时绑定完整 Plan manifest、connector registry 与 atomic Bundle 摘要；Runner queue 绑定
精确 Environment UUID 及这三个摘要的 domain-separated deployment hash，防止另一环境、不兼容 Bundle
或同 Bundle 的旧 Plan Runner 拾取 Task。旧、新 digest Worker 必须按各自 exact queue 共存到对应 Workflow
和 Task 全部终态，不能让请求正文选择 queue、Plan 或 Bundle。

Runner queue v2 是在 C2-4b 协议尚未装配、dispatcher 与 claims 均关闭、没有真实 v2 Workflow History 时
完成的首发前修正，因此不需要对已运行 History 使用 `GetVersion`。任何外部开发环境若曾绕过该门禁持久化
旧实验 History，都必须在隔离 namespace 中清理或显式迁移，不能用新版代码直接 replay 旧 v1 Runner queue。
后续 live assembly rollout 必须先预热新 control 与 Runner exact queues，再让 dispatcher 启动新 Workflow；
旧两类 Worker 要保留到其对应 Workflow/Task 全部终态后才能 drain，不能靠共享队列做版本兼容。

## History allowlist

所有 v2 DTO 使用严格 JSON，拒绝未知、重复、大小写别名、尾随文档和超过 4096 字节的文档。
History 只允许下列事实：

- Outbox、Tenant、Workspace、Signal、Incident、Environment、Service、Investigation、Task、Evidence ID；
- Task position、逻辑 round、aggregate version 和有界状态；
- manifest、registry、profile、tasks、bundle 与 Evidence content SHA-256。

History 不得出现 Signal 正文、TaskSpec/input、connector 查询、target/endpoint、credential role/value、
bearer、lease token、Runner/证书、scope revision、Evidence items、receipt provenance、远端 header/body/error
或 panic 文本。Runner Activity 只返回 `NOT_CLAIMED`、`COMPLETE_ACKNOWLEDGED` 或
`RECOVERY_REQUIRED`；这些状态都不是数据库终态证明。

## 确定性状态机

Preparation 在 disconnected Workflow context 中完成既有幂等持久化，并回读精确 Environment、Service
和最多 12 个连续 Task reference。无活动 Incident 时返回 `NO_ACTIVE_INCIDENT`。

有 Task 时按 position 严格串行执行，每个 Task 最多三个逻辑 round：

1. 在精确 Runner queue 调度一次 Runner Activity；Temporal `MaximumAttempts=1`、
   `WaitForCancellation=true`、`DisableEagerExecution=true`，不允许 SDK 或服务端重发一次性完成正文。
2. 不论 Runner 返回成功状态、错误、超时或无响应，立即在 control queue 调用 DB-only Recovery。
3. 只有 Recovery 的 `COMMITTED` 或 `CONTROL_CANCELLED` 是可信终态；Workflow 只从 Recovery 投影
   Task status、Evidence ID 和 content hash。
4. Runner 报告 `COMPLETE_ACKNOWLEDGED` 而 Recovery 仍为 `PENDING` 时，作为持久事实冲突固定失败。
5. 其余 `PENDING` 等待固定 35 秒后再次 Recovery；仍为 `PENDING` 才进入下一逻辑 round。
6. 三个 round 后仍未收敛，Workflow 以固定 `READ_TASK_PENDING` 失败，不把未知结果伪装成 Task 失败，
   也不修改 PostgreSQL 终态。

普通 Workflow Cancel 不会立即中断一次性 Runner/Recovery 边界。READ orchestration 使用 disconnected
context 继续执行同一个三轮预算；若所有 Task 得到数据库终态，之后才向调用方返回取消。若三轮后仍为
`PENDING`，Workflow 不确认取消，也不伪造终态，而以固定 non-retryable `READ_TASK_PENDING` 失败；该失败
History 是 durable manual-reconciliation handoff。C2-4c 必须监控并告警该 error type，保留 Task/Workflow，
在数据库事实收敛或运维处置后 Reset/重放；该 supervisor 上线前不得开启 claims。Temporal Terminate 仍只
用于有审计的紧急硬停；它不等价于普通 Cancel，后续同样必须由运维恢复流程核对持久 Task。

## READ Runner Activity

生产构造器只接受由 `readrunnerclient.New` 创建且仍可 Claim 的具体 READ mTLS client、完整且不可复制的
`readruntime.Bundle`、精确 Plan manifest digest，以及非空、服从 context 的可信
`readexecutor.BearerSource`。Connector registry digest 必须从 Bundle 自身取得，不能由 Task 或配置另行
提交。测试 fake 只能通过包内私有端口使用；没有 anonymous、unbound Plan、静态 token、credential-free
或 WRITE fallback。

任何 Gateway 请求前，Activity 必须验证输入 Plan/Registry 与进程 Snapshot 完全相等，以及 exact
Workflow/Activity ID、namespace、run ID、Environment/deployment queue、单次 attempt、
timeout/retry/priority 和输入 Bundle digest。Claim 返回的 Descriptor 在 Bundle Prepare 前再次核对
Plan/Registry，不能仅依赖队列路由。
Temporal heartbeat 在这些检查后立即发送，并由独立 5 秒 supervisor 覆盖 Claim、Prepare、Start、Execute
和 Complete；Gateway heartbeat 仅在 Start 后每 10 秒递增发送，二者不能共用定时器。

执行顺序固定为：

1. 用 scheduler-owned safe IDs 和四个 Plan digest Claim 精确 Task；
2. Bundle 仅从 Gateway 返回且与 expected facts 匹配的 Descriptor 准备 one-shot execution；
3. GO 前失败只允许用无 value、固定 5 秒 cleanup context 尝试一次 Release；只有 Release ACK 才返回
   `NOT_CLAIMED`，否则要求 DB Recovery；
4. Start 返回的 opaque capability 转换为不可伪造的 execution start 后才执行固定 HTTP adapter；
5. context cancel、heartbeat `TERMINATE`、heartbeat 错误或 executor 错误都先取消并等待 executor goroutine
   退出，再返回 `RECOVERY_REQUIRED`；
6. Complete 最多调用一次。任何 Complete 错误或未知响应都不得重发 Evidence，由 Workflow 查询数据库。

bearer、Lease、Start capability、Prepared material、Evidence body 和 completion receipt 均不进入 Activity
输出或普通格式化。Activity 返回前必须停止 Temporal heartbeat supervisor、销毁本地 Lease bearer，并在
Start 后确认 executor 已收敛。

## 部署与后续门禁

C2-4b 只能作为库和 testsuite 契约合并。C2-4c 才能在单一 assembly factory 中加载 plan、connector、
target、egress、Bundle 和部署摘要，创建角色分离的 Temporal client/worker，安装真实 Outbox supervisor、
`READ_TASK_PENDING` durable-handoff 监控、Gateway callbacks 与 READ Runner，并完成 PostgreSQL 16 + Temporal + mTLS Gateway + TLS 数据源的本地
Signal→Evidence E2E。

即使 C2-4c 完成，以下证据齐备前 Admission 仍必须关闭：真实 context-compliant Bearer provider、
Heartbeat 事务内 Bundle 重新授权、企业 PKI/Temporal RBAC、NetworkPolicy/egress、源侧 DLP、无混版
drain/rollout、replay 与故障演练、以及签名 Go/No-Go。fake 或本地契约测试不能冒充外部验收。
