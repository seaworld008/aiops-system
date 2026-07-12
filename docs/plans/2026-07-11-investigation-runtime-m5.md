# M5 Investigation Runtime 信任边界与后续依赖

日期：2026-07-11
范围：M5A1 领域契约与 Memory fixture、M5A2a PostgreSQL 运行时迁移、M5A2b 事务型 PostgreSQL Repository、M5B1 READ Runner 持久 attempt/fence 底座、M5B2 独立 READ Task Gateway 协议，以及 M5B3 精确环境 TaskSpec scope 与 immutable typed connector registry

## 信任边界

- Signal、TaskSpec、连接器返回正文和模型输出均为不可信输入。进入领域事实前必须完成 Workspace 作用域校验、长度与低基数字段校验、对象型 JSON 校验和 SHA-256 完整性校验。JSON 字段名与赋值名按仅保留 Unicode 字母数字的骨架检查，并拒绝控制/格式字符、敏感 CLI 长选项及双向/零宽混淆。
- TaskSpec 只能引用服务端登记的 `ConnectorID` 与有界操作名；Memory/PostgreSQL 构造必须注入非空可信 `TaskSpecAuthorizer`，并先从锁定的 Incident 持久事实构造精确 Tenant/Workspace/Environment/Service/MappingStatus scope，再按 ConnectorID/Operation 和 typed input allowlist 校验 canonical spec。只有 `EXACT` mapping 可创建 READ Task，scope 不能由请求提供或覆盖。TaskSpec 不得携带 URL、endpoint、host、destination、args/env/command/options、header、Authorization、auth、secret、token、password 或 credential。连接目标和连接凭据只能由后续 READ Runner target manifest 通过服务端不透明 `TargetRef` 解析；不得使用包级可变 registry。
- Workspace 是仓储查询、关联和幂等记录的隔离边界。跨 Workspace 的 Signal、Incident、Investigation、Task、Evidence 和 Hypothesis 引用不得解析为同一事实。
- Tenant 与 Workspace 的映射只能来自 Memory 构造时必填的可信 `TenantResolver`；不得把外部传入的 Workspace 直接当作 Tenant。`NewIncident` 仅供 tenant/workspace 相同的遗留调用，Memory 和后续持久化仓储必须使用可信映射并调用 `NewIncidentForTenant`。
- RunnerEvidenceReceipt 只接收有界 ID、连接器引用、内容哈希或低基数失败码。credential、Authorization header 和原始错误体不属于该契约，也不得进入 Evidence、Feedback 或模型提案 JSON。
- 模型不属于可信计算基。Hypothesis 必须引用已持久化 Evidence；只有认证的人类 Feedback 可以确认或驳回 Hypothesis，并由确认操作更新 Incident 的 `ConfirmedHypothesisID`。
- Memory 仓储只是并发、幂等和别名隔离测试的 fixture，不是生产事实源，不提供持久性、跨进程一致性或恢复保证。

### PostgreSQL 与 Runner 入口约束

- Memory 为了测试作用域碰撞、ID factory 冲突和别名隔离，允许使用符合领域语法的普通字符串 ID；PostgreSQL adapter 已在进入 SQL 前把所有持久化资源 ID 收窄为小写 RFC 4122 UUID v1–v5。每条业务查询、数据库时间查询、advisory lock 和复合外键都显式携带 Tenant/Workspace，不能把 UUID 的全局唯一性当作租户授权。
- 通用 `Repository.CompleteTask` 是领域持久化契约，不是 PostgreSQL Runner ingress。不得从 HTTP/Runner 请求正文信任 `RunnerID`、Workspace、Environment、scope revision 或证书指纹并直接调用该方法。
- M5B Runner Gateway 必须从已验证的 mTLS 连接派生不可序列化的 `RunnerScope` 与叶证书 SHA-256，并在同一 PostgreSQL 事务中重新锁定和校验：Runner 仍 enabled、pool 为 `READ`、scope revision 仍为当前值、存在精确的 `(workspace_id, environment_id)` binding、证书仍为 `ACTIVE` 且处于有效期。只有这个可信事务入口才能写入 `runner_evidence_receipts`；请求正文不能覆盖任何认证字段。
- `000011` 使用 append-history `investigation_task_attempts` 保存每个 Task 的递增 epoch、lease token SHA-256、精确 Runner/scope revision/证书快照、严格 heartbeat sequence 与租期。Token source 必须移交恰好 32 个随机字节，仓储编码为固定 43 字符无填充 base64url bearer；bearer 只存在于进程内可销毁的 `Claim/Fence` 及唯一一次 Claim 响应 JSON，不得进入请求 JSON、SQL、日志、trace 或审计。每个 Task 同时至多一个 `LEASED/RUNNING` attempt；`LEASED → RUNNING → COMPLETED`，GO 前可 `RELEASED`，活动 attempt 可因过期或取消进入 `EXPIRED/CANCELLED`，所有终态、服务端时间戳和 fence 均不可改写。
- `runner_evidence_receipts` 以 expand-first 方式保留既有 v1 行并增加 v2 `lease_epoch` fence；迁移后禁止新写 v1。v2 receipt 必须与同 Task/Runner/scope revision/证书/epoch/request hash/receipt hash 的 `COMPLETED` attempt 精确匹配，且 Evidence、Task 终态、attempt 与 receipt 在一个事务提交。相同 epoch 与相同规范结果返回原 ID；不同结果失败，旧 token/epoch 不能写入新 attempt。
- READ 完成正文只能包含有界结构化 Evidence items 或固定低敏失败码，不存在 Runner 可控的 `truncated` 信任位；无法满足完整 typed connector 契约时必须把该 Task 作为失败返回，由多个 Task 结果推导 `PARTIAL` Investigation。Connector、Operation、Workspace、Environment、Runner、scope revision、证书、item count、幂等键和所有 SHA-256 均由已持久化事实与服务端 JCS 投影生成；正文不能提交 source、目标 URL、header、credential、原始错误体或自选 hash。M5B2 已把 completion 收窄到强制 `CompleteRunnerAuthorizedTx`：typed output 回调在 Task/Attempt/Investigation 锁内、任何 Evidence 写入前运行，且只能看到 detached Descriptor/Evidence，不能接触 Fence 或 bearer。通用安全 JSON 校验继续只作为纵深防御。
- `internal/readtask/postgres` 是 caller-owned transaction 的低层组件，不是独立授权边界。调用者必须先在同一事务执行 `runneridentity/postgres.AuthenticateTx`，再调用 READ attempt 操作，并在任一错误时回滚；`Start` 与 `Complete` 分别只保留强制 `StartRunnerAuthorizedTx`、`CompleteRunnerAuthorizedTx` 入口。数据库触发器会再次校验当前精确身份，允许身份漂移后的 fail-safe `CANCELLED/EXPIRED`，并按 identity → Task → attempt → Investigation 的顺序取锁后才读取安全时间。
- `000010` 与 `000011` 会对既有依赖表取得确定顺序的 `ACCESS EXCLUSIVE` 锁。部署前必须 drain Control Plane、Gateway、Worker、Outbox dispatcher 和旧 Store 等全部数据库写入者，并用有限 `lock_timeout` 将无法及时取得锁视为发布失败；失败时依靠迁移事务完整回滚，确认旧版本恢复写入前不得启动新 Worker/Gateway。`000011` down 只有在 attempt history 与 v2 receipt 均为空时才允许执行。承载应用对象的 schema 只能允许可信迁移角色创建对象，避免固定函数 `search_path` 下的对象替换。
- 同一 Investigation 的并发写统一先按 position/ID 锁定 ReadTask，再锁定 Investigation；Evidence 准入与 Task 终态约束都遵守该顺序。仓储不得先持有 Investigation 行锁再等待 ReadTask，以免与数据库约束形成反序死锁。
- Runner Evidence receipt 的身份复核按 scope binding → registration → certificate 顺序加锁，与 scope binding 删除后递增 registration revision 的既有触发器保持一致；不得在持有 registration 行锁时反向等待 binding。

## 状态机

| 实体 | 状态与允许方向 |
| --- | --- |
| Incident | `OPEN → INVESTIGATING → MITIGATING → RESOLVED → CLOSED`；只有 `OPEN/INVESTIGATING/MITIGATING` 参与 Signal 活动归并。 |
| Investigation | `QUEUED → RUNNING → COMPLETED/PARTIAL`；`FailInvestigation` 可将 `QUEUED/RUNNING` 原子推进到 `FAILED`，显式取消可进入 `CANCELLED`。两种终态写入都会取消尚未终态的子任务、保留已有 Evidence/终态任务并释放活动调查槽位。同一 Incident 同时最多一个 `QUEUED/RUNNING` Investigation；`FailureCode` 只允许出现在 `FAILED/CANCELLED`。 |
| ModelStatus | 状态矩阵固定为 `QUEUED=PENDING`、`RUNNING=PENDING/RUNNING`、`COMPLETED/PARTIAL=COMPLETED/FAILED/SKIPPED`、`FAILED/CANCELLED=CANCELLED`。显式 `StartModel` 仅在全部 ReadTask 已终态时持久化 `PENDING → RUNNING`，防止模型与证据集合并发漂移；`COMPLETED/FAILED` 只能从 `RUNNING` finalize。无模型配置进入 `SKIPPED`，取消进入独立 `CANCELLED`，不得冒充 `SKIPPED`。 |
| ReadTask | `QUEUED → RUNNING → EVIDENCE/FAILED/CANCELLED`；Memory fixture 允许以原子 complete 从 `QUEUED` 写入终态，并同时推进 Investigation 到 `RUNNING`。父 Investigation 失败或取消时，所有 `QUEUED/RUNNING` 子任务在同一临界区进入 `CANCELLED`，既有终态不回退。 |
| READ Attempt | `LEASED → RUNNING → COMPLETED`；`LEASED` 可在执行前 `RELEASED`，`LEASED/RUNNING` 可进入 `EXPIRED/CANCELLED`。只有 `RUNNING` 可 heartbeat，sequence 必须逐一递增；`COMPLETED` 必须存在不可变 v2 receipt。 |
| Hypothesis | `PROPOSED → CONFIRMED/REJECTED`；`CONFIRMED` 和 `REJECTED` 只能来自人类 Feedback。 |

终态写入必须绑定 Workspace、幂等键和规范化请求哈希；同键同请求返回原结果，同键不同请求失败。`internal/investigation` 提供 Memory 与后续 PostgreSQL 仓储共用的纯请求语义函数：正文先完成校验和深拷贝，再以版本化 operation schema、NUL 域分隔符和 JCS wire 生成 SHA-256。Create 与 TaskSpec 分别固定为 `investigation.create.v1`、`investigation.task-specs.v1`。Evidence Payload 与 Hypothesis Proposal 始终保留原始字节，并由其原始 SHA-256 参与语义哈希；不得用 JCS 改写这两类事实。Feedback Details 则在首次写入前通过严格安全 JSON 校验并保存为 JCS，因此仅空白或对象键顺序不同的重放具有相同语义。

Hypothesis `confidence` 到遗留 `confidence_band` 的映射固定为：`[0, 0.5) → LOW`、`[0.5, 0.8) → MEDIUM`、`[0.8, 1] → HIGH`。迁移 CHECK 与 PostgreSQL adapter 共用这组边界，禁止调用方直接提供或覆盖 band。

可变的服务端准入不能破坏已提交事实的幂等重放。Create 必须先用纯 canonical/hash 检查已有 operation owner 和 idempotency record；精确同键重放返回既有事实且不重新运行可变 authorizer。只有尚无记录的新请求才在 Memory 写锁或 PostgreSQL 事务中锁定可信 Incident、构造精确 scope 并调用纯内存 O(1) `TaskSpecAuthorizer`；新 key 绑定活动 Investigation 也必须重新准入，拒绝发生在任何 Investigation/Task/Incident 状态或幂等账本写入前。Signal 同样先应用静态安全规范化并检查既有事实；5 分钟 future-skew 只约束不存在的新 Signal，可信时钟回拨不能使历史重放失败。

幂等操作响应与当前查询投影是两个不同契约。`StartModel` 和 `FinalizeInvestigation` 首次成功时保存独立深拷贝的响应快照；后续同键重放永远返回首次快照，即使 Investigation 已 finalize/fail，或 Feedback 已把实时 Hypothesis 投影从 `PROPOSED` 改为 `CONFIRMED/REJECTED`。调用方对首次结果或重放结果的修改也不得反向修改快照；需要最新状态时必须调用 Get/List 查询。

Memory 的提交时间以可信时钟和已持久化相关事实取单调上界，防止时钟回拨产生倒序生命周期；Create 在锁内完成 ID 准备后，以 clock 与 Incident 的 `OpenedAt/LastSignalAt/UpdatedAt` 上界作为 Investigation、Tasks 和 Incident transition 的同一提交时间。Evidence 的 `CollectedAt` 不得晚于提交边界。`ListEvidence` 明确按 `CollectedAt → CreatedAt → ID` 升序返回，因此结果不依赖并发任务的完成/加锁顺序。

PostgreSQL 的 StartModel/Finalize 响应快照使用 JCS、SHA-256 和版本化 DTO；decode 与 encode 都验证完整聚合图、持久 UUID、父子 scope、Rank/ID 唯一性和固定状态结果。快照硬上限为 8 MiB，可容纳领域允许的 20 个最大有界 Hypothesis 包络；未知数据库约束错误一律保持脱敏 persistence failure，只有具体操作识别的命名约束才能映射为领域冲突。生命周期更新遵守 Task → Investigation，Incident admission/Feedback 遵守 Incident → Investigation；Investigation 的 Incident snapshot 只在 INSERT 准入时锁定并验证，后续不可变 lifecycle UPDATE 不反向获取 Incident 行锁。

Signal 关联会为已处理的 resolved 输入保存关联结果（包括“当时没有活动 Incident”的 no-op tombstone）。同一 resolved Signal 的重放只能返回原关联语义，不能因之后出现新的 firing Incident 而被重新解释或重复计数。

Signal 的 Provider 使用小写低基数语法，ProviderEventID/Fingerprint 使用有界安全 Unicode；`ObservedAt` 在写入前去除 monotonic 部分并规范到 UTC，只允许领先可信时钟最多 5 分钟。活动 Incident 归并还必须精确匹配 `MappingStatus/ServiceID/EnvironmentID`，不匹配时 fail closed 且不得计数或写 association。

当前 Get/List 仅是进程内 Memory fixture 与后续仓储的内部接口，不是公开 HTTP 分页契约，也不应被直接暴露为无界 API。公共查询的 cursor、page size、稳定 continuation 与授权语义留到 M5D HTTP/API 设计统一定义；在该设计落地前不新增临时公共分页形状。

## M5B–D 依赖

- M5B1 已在 `000010` 调查运行时与 `000011` Runner ingress 迁移之上建立 READ Runner attempt、lease fencing、严格 heartbeat、GO 前 release、重试与 Evidence/receipt 原子事务。M5B2 已新增独立于 WRITE `/jobs*` 的 `/runner/v1/read-tasks/{task_id}:claim|start|heartbeat|release|complete`，使用专属 43 字符 bearer、严格 JSON/RFC 9457，并固定执行外层即时身份预检及内层 `Begin → AuthenticateTx → READ task Tx → Commit`。请求正文不能提供 Runner、scope、证书、Workspace、Environment、connector target 或任何 hash。
- M5B3 已新增不可变、无热更新的首批 typed registry：`prometheus/range_query` 与 `victorialogs/search` 都只接受 `lookback_minutes`，固定查询、字段投影、预算和不透明 `TargetRef` 全部来自严格 admission manifest；Prometheus matrix 与 VictoriaLogs primitive projection 分别执行 connector-specific output schema。ConnectorID 使用完整 SHA-256 内容地址绑定 scope、TargetRef、查询、投影、预算与冻结的 validator-v1 profile，旧 Task 不能被同名新契约重新解释；registry digest 不覆盖 Secret。`TargetRef` 的 hash suffix 必须由后续 READ Runner target-manifest loader 对 endpoint identity、显式 CA、credential/role ref 与网络策略重新计算，完成前 claims 保持关闭。
- Control Plane 装配仍有意保持 READ claims disabled，并继续使用原 disabled start/completion callbacks；仅 claim 关闭不足以阻止升级前遗留 lease 前进。M5C 必须接通 Temporal/Outbox、READ Runner 固定执行器、独立 target manifest 与 Gateway/Runner digest 一致性门禁后，才能在单独 assembly PR 原子替换 callbacks 并考虑开启 claims。Workflow/History 只传 ID 和小型脱敏 receipt，不接受 TaskSpec 注入目标或凭据。通用敏感词黑名单不能替代 schema allowlist 这一主控制。
- M5D 必须实现模型路由、结构化 Hypothesis 校验、确定性证据报告、人工 Feedback 与离线评测。模型失败和无模型配置不得吞掉 Evidence，也不得升级为生产动作授权。

## 生产写不存在启用路径

M5A1–M5B3 增加领域/Memory fixture、调查事实 schema、READ attempt/fence、PostgreSQL 持久化闭环、仅位于 `:8443` mTLS listener 的受信 READ Task Gateway，以及尚未接入 live runtime 的 typed connector registry；它不包含 Temporal Workflow，也不是公共 HTTP API。Control Plane 仍安装 disabled callbacks，因此 READ claim 与遗留 lease 均 fail closed。调查结果没有连接到 ActionPlan、策略、审批、执行器或 production-write feature flag；生产写继续不存在可配置启用路径。
