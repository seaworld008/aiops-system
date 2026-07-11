# M5 Investigation Runtime 信任边界与后续依赖

日期：2026-07-11
范围：M5A1 领域契约与 Memory fixture、M5A2a PostgreSQL 运行时迁移，以及 M5A2b 事务型 PostgreSQL Repository

## 信任边界

- Signal、TaskSpec、连接器返回正文和模型输出均为不可信输入。进入领域事实前必须完成 Workspace 作用域校验、长度与低基数字段校验、对象型 JSON 校验和 SHA-256 完整性校验。JSON 字段名与赋值名按仅保留 Unicode 字母数字的骨架检查，并拒绝控制/格式字符、敏感 CLI 长选项及双向/零宽混淆。
- TaskSpec 只能引用服务端登记的 `ConnectorID` 与有界操作名；Memory 构造必须注入非空可信 `TaskSpecAuthorizer`，按 Workspace、精确 ConnectorID/Operation 组合和 typed input allowlist 再校验 canonical spec。不得携带 URL、endpoint、host、destination、args/env/command/options、header、Authorization、auth、secret、token、password 或 credential。连接目标和连接凭据只能由后续 Gateway 在服务端解析；不得使用包级可变 registry。
- Workspace 是仓储查询、关联和幂等记录的隔离边界。跨 Workspace 的 Signal、Incident、Investigation、Task、Evidence 和 Hypothesis 引用不得解析为同一事实。
- Tenant 与 Workspace 的映射只能来自 Memory 构造时必填的可信 `TenantResolver`；不得把外部传入的 Workspace 直接当作 Tenant。`NewIncident` 仅供 tenant/workspace 相同的遗留调用，Memory 和后续持久化仓储必须使用可信映射并调用 `NewIncidentForTenant`。
- RunnerEvidenceReceipt 只接收有界 ID、连接器引用、内容哈希或低基数失败码。credential、Authorization header 和原始错误体不属于该契约，也不得进入 Evidence、Feedback 或模型提案 JSON。
- 模型不属于可信计算基。Hypothesis 必须引用已持久化 Evidence；只有认证的人类 Feedback 可以确认或驳回 Hypothesis，并由确认操作更新 Incident 的 `ConfirmedHypothesisID`。
- Memory 仓储只是并发、幂等和别名隔离测试的 fixture，不是生产事实源，不提供持久性、跨进程一致性或恢复保证。

### PostgreSQL 与 Runner 入口约束

- Memory 为了测试作用域碰撞、ID factory 冲突和别名隔离，允许使用符合领域语法的普通字符串 ID；PostgreSQL adapter 已在进入 SQL 前把所有持久化资源 ID 收窄为小写 RFC 4122 UUID v1–v5。每条业务查询、数据库时间查询、advisory lock 和复合外键都显式携带 Tenant/Workspace，不能把 UUID 的全局唯一性当作租户授权。
- 通用 `Repository.CompleteTask` 是领域持久化契约，不是 PostgreSQL Runner ingress。不得从 HTTP/Runner 请求正文信任 `RunnerID`、Workspace、Environment、scope revision 或证书指纹并直接调用该方法。
- M5B Runner Gateway 必须从已验证的 mTLS 连接派生不可序列化的 `RunnerScope` 与叶证书 SHA-256，并在同一 PostgreSQL 事务中重新锁定和校验：Runner 仍 enabled、pool 为 `READ`、scope revision 仍为当前值、存在精确的 `(workspace_id, environment_id)` binding、证书仍为 `ACTIVE` 且处于有效期。只有这个可信事务入口才能写入 `runner_evidence_receipts`；请求正文不能覆盖任何认证字段。
- `000010` 会对既有依赖表取得确定顺序的 `ACCESS EXCLUSIVE` 锁。部署前必须 drain Control Plane、Gateway、Worker、Outbox dispatcher 和旧 Store 等全部数据库写入者，并用有限 `lock_timeout` 将无法及时取得锁视为发布失败；失败时依靠迁移事务完整回滚，确认旧版本恢复写入前不得启动新 Worker/Gateway。承载应用对象的 schema 只能允许可信迁移角色创建对象，避免固定函数 `search_path` 下的对象替换。
- 同一 Investigation 的并发写统一先按 position/ID 锁定 ReadTask，再锁定 Investigation；Evidence 准入与 Task 终态约束都遵守该顺序。仓储不得先持有 Investigation 行锁再等待 ReadTask，以免与数据库约束形成反序死锁。
- Runner Evidence receipt 的身份复核按 scope binding → registration → certificate 顺序加锁，与 scope binding 删除后递增 registration revision 的既有触发器保持一致；不得在持有 registration 行锁时反向等待 binding。

## 状态机

| 实体 | 状态与允许方向 |
| --- | --- |
| Incident | `OPEN → INVESTIGATING → MITIGATING → RESOLVED → CLOSED`；只有 `OPEN/INVESTIGATING/MITIGATING` 参与 Signal 活动归并。 |
| Investigation | `QUEUED → RUNNING → COMPLETED/PARTIAL`；`FailInvestigation` 可将 `QUEUED/RUNNING` 原子推进到 `FAILED`，显式取消可进入 `CANCELLED`。两种终态写入都会取消尚未终态的子任务、保留已有 Evidence/终态任务并释放活动调查槽位。同一 Incident 同时最多一个 `QUEUED/RUNNING` Investigation；`FailureCode` 只允许出现在 `FAILED/CANCELLED`。 |
| ModelStatus | 状态矩阵固定为 `QUEUED=PENDING`、`RUNNING=PENDING/RUNNING`、`COMPLETED/PARTIAL=COMPLETED/FAILED/SKIPPED`、`FAILED/CANCELLED=CANCELLED`。显式 `StartModel` 仅在全部 ReadTask 已终态时持久化 `PENDING → RUNNING`，防止模型与证据集合并发漂移；`COMPLETED/FAILED` 只能从 `RUNNING` finalize。无模型配置进入 `SKIPPED`，取消进入独立 `CANCELLED`，不得冒充 `SKIPPED`。 |
| ReadTask | `QUEUED → RUNNING → EVIDENCE/FAILED/CANCELLED`；Memory fixture 允许以原子 complete 从 `QUEUED` 写入终态，并同时推进 Investigation 到 `RUNNING`。父 Investigation 失败或取消时，所有 `QUEUED/RUNNING` 子任务在同一临界区进入 `CANCELLED`，既有终态不回退。 |
| Hypothesis | `PROPOSED → CONFIRMED/REJECTED`；`CONFIRMED` 和 `REJECTED` 只能来自人类 Feedback。 |

终态写入必须绑定 Workspace、幂等键和规范化请求哈希；同键同请求返回原结果，同键不同请求失败。`internal/investigation` 提供 Memory 与后续 PostgreSQL 仓储共用的纯请求语义函数：正文先完成校验和深拷贝，再以版本化 operation schema、NUL 域分隔符和 JCS wire 生成 SHA-256。Create 与 TaskSpec 分别固定为 `investigation.create.v1`、`investigation.task-specs.v1`。Evidence Payload 与 Hypothesis Proposal 始终保留原始字节，并由其原始 SHA-256 参与语义哈希；不得用 JCS 改写这两类事实。Feedback Details 则在首次写入前通过严格安全 JSON 校验并保存为 JCS，因此仅空白或对象键顺序不同的重放具有相同语义。

Hypothesis `confidence` 到遗留 `confidence_band` 的映射固定为：`[0, 0.5) → LOW`、`[0.5, 0.8) → MEDIUM`、`[0.8, 1] → HIGH`。迁移 CHECK 与 PostgreSQL adapter 共用这组边界，禁止调用方直接提供或覆盖 band。

可变的服务端准入不能破坏已提交事实的幂等重放。Create 必须先用纯 canonical/hash 在读锁下检查已有 operation owner 和 idempotency record；只有新请求才在锁外调用 `TaskSpecAuthorizer`，并在写锁内二次检查并发赢家后创建。Signal 同样先应用静态安全规范化并检查既有事实；5 分钟 future-skew 只约束不存在的新 Signal，可信时钟回拨不能使历史重放失败。

幂等操作响应与当前查询投影是两个不同契约。`StartModel` 和 `FinalizeInvestigation` 首次成功时保存独立深拷贝的响应快照；后续同键重放永远返回首次快照，即使 Investigation 已 finalize/fail，或 Feedback 已把实时 Hypothesis 投影从 `PROPOSED` 改为 `CONFIRMED/REJECTED`。调用方对首次结果或重放结果的修改也不得反向修改快照；需要最新状态时必须调用 Get/List 查询。

Memory 的提交时间以可信时钟和已持久化相关事实取单调上界，防止时钟回拨产生倒序生命周期；Create 在锁内完成 ID 准备后，以 clock 与 Incident 的 `OpenedAt/LastSignalAt/UpdatedAt` 上界作为 Investigation、Tasks 和 Incident transition 的同一提交时间。Evidence 的 `CollectedAt` 不得晚于提交边界。`ListEvidence` 明确按 `CollectedAt → CreatedAt → ID` 升序返回，因此结果不依赖并发任务的完成/加锁顺序。

PostgreSQL 的 StartModel/Finalize 响应快照使用 JCS、SHA-256 和版本化 DTO；decode 与 encode 都验证完整聚合图、持久 UUID、父子 scope、Rank/ID 唯一性和固定状态结果。快照硬上限为 8 MiB，可容纳领域允许的 20 个最大有界 Hypothesis 包络；未知数据库约束错误一律保持脱敏 persistence failure，只有具体操作识别的命名约束才能映射为领域冲突。生命周期更新遵守 Task → Investigation，Incident admission/Feedback 遵守 Incident → Investigation；Investigation 的 Incident snapshot 只在 INSERT 准入时锁定并验证，后续不可变 lifecycle UPDATE 不反向获取 Incident 行锁。

Signal 关联会为已处理的 resolved 输入保存关联结果（包括“当时没有活动 Incident”的 no-op tombstone）。同一 resolved Signal 的重放只能返回原关联语义，不能因之后出现新的 firing Incident 而被重新解释或重复计数。

Signal 的 Provider 使用小写低基数语法，ProviderEventID/Fingerprint 使用有界安全 Unicode；`ObservedAt` 在写入前去除 monotonic 部分并规范到 UTC，只允许领先可信时钟最多 5 分钟。活动 Incident 归并还必须精确匹配 `MappingStatus/ServiceID/EnvironmentID`，不匹配时 fail closed 且不得计数或写 association。

当前 Get/List 仅是进程内 Memory fixture 与后续仓储的内部接口，不是公开 HTTP 分页契约，也不应被直接暴露为无界 API。公共查询的 cursor、page size、稳定 continuation 与授权语义留到 M5D HTTP/API 设计统一定义；在该设计落地前不新增临时公共分页形状。

## M5B–D 依赖

- M5B 必须在 `000010` 和事务型 PostgreSQL Repository 之上实现认证的 READ Runner 任务领取、lease fencing、重试与取消。通用 `Repository.CompleteTask` 继续 fail closed；只有 mTLS Gateway 从服务端 Runner 注册、精确 scope binding 和证书状态派生身份后，才能在同一事务写入 Evidence 与 receipt。
- M5C 必须接通 Temporal/Outbox。Workflow/History 只传 ID 和小型脱敏 receipt；连接器目标由 Gateway 服务端配置解析，不接受 TaskSpec 注入目标或凭据。Gateway 只有按已登记 ConnectorID/Operation 的 output schema 完成 typed projection 与 redaction 后，才能进入受信任务完成事务；通用敏感词黑名单只能作为纵深防御，不能替代 schema allowlist 这一主控制。
- M5D 必须实现模型路由、结构化 Hypothesis 校验、确定性证据报告、人工 Feedback 与离线评测。模型失败和无模型配置不得吞掉 Evidence，也不得升级为生产动作授权。

## 生产写不存在启用路径

M5A1–M5A2b 只增加领域/Memory fixture、调查事实 schema 与 PostgreSQL 持久化闭环，不包含 Temporal Workflow、受信调查 Runner Gateway 路由或公共 HTTP API；也没有把调查结果连接到 ActionPlan、策略、审批、执行器或 production-write feature flag。PostgreSQL 的通用任务完成入口明确 fail closed，不能从请求正文接受 Runner 身份。后续里程碑在完整策略、审批、短期凭据、隔离 Runner 和执行审计链全部落地前，必须继续保持生产写不可达。
