# M5 Investigation Runtime 信任边界与后续依赖

日期：2026-07-11
范围：M5A1 领域契约与仅供 fixture 使用的 Memory 调查仓储

## 信任边界

- Signal、TaskSpec、连接器返回正文和模型输出均为不可信输入。进入领域事实前必须完成 Workspace 作用域校验、长度与低基数字段校验、对象型 JSON 校验和 SHA-256 完整性校验。
- TaskSpec 只能引用服务端登记的 `ConnectorID` 与有界操作名；不得携带 URL、endpoint、header、Authorization、auth、secret、token、password 或 credential。连接目标和连接凭据只能由后续 Gateway 在服务端解析。
- Workspace 是仓储查询、关联和幂等记录的隔离边界。跨 Workspace 的 Signal、Incident、Investigation、Task、Evidence 和 Hypothesis 引用不得解析为同一事实。
- RunnerEvidenceReceipt 只接收有界 ID、连接器引用、内容哈希或低基数失败码。credential、Authorization header 和原始错误体不属于该契约，也不得进入 Evidence、Feedback 或模型提案 JSON。
- 模型不属于可信计算基。Hypothesis 必须引用已持久化 Evidence；只有认证的人类 Feedback 可以确认或驳回 Hypothesis，并由确认操作更新 Incident 的 `ConfirmedHypothesisID`。
- Memory 仓储只是并发、幂等和别名隔离测试的 fixture，不是生产事实源，不提供持久性、跨进程一致性或恢复保证。

## 状态机

| 实体 | 状态与允许方向 |
| --- | --- |
| Incident | `OPEN → INVESTIGATING → MITIGATING → RESOLVED → CLOSED`；只有 `OPEN/INVESTIGATING/MITIGATING` 参与 Signal 活动归并。 |
| Investigation | `QUEUED → RUNNING → COMPLETED/PARTIAL`；确定性内部失败可进入 `FAILED`，取消可进入 `CANCELLED`。同一 Incident 同时最多一个 `QUEUED/RUNNING` Investigation；`FailureCode` 只允许出现在 `FAILED/CANCELLED`。 |
| ModelStatus | `PENDING → RUNNING → COMPLETED/FAILED`；显式 `StartModel` 持久化 `PENDING → RUNNING`，`COMPLETED/FAILED` 只能从 `RUNNING` finalize。无模型配置从 `PENDING` 进入 `SKIPPED`；取消从 `PENDING/RUNNING` 进入独立的 `CANCELLED`，不得冒充 `SKIPPED`。报告生成独立于模型：所有 ReadTask 有 Evidence 时，即使模型 `FAILED/SKIPPED`，Investigation 仍为 `COMPLETED`；任一 Task 失败或取消则为 `PARTIAL`。 |
| ReadTask | `QUEUED → RUNNING → EVIDENCE/FAILED/CANCELLED`；Memory fixture 允许以原子 complete 从 `QUEUED` 写入终态，并同时推进 Investigation 到 `RUNNING`。 |
| Hypothesis | `PROPOSED → CONFIRMED/REJECTED`；`CONFIRMED` 和 `REJECTED` 只能来自人类 Feedback。 |

终态写入必须绑定 Workspace、幂等键和规范化请求哈希；同键同请求返回原结果，同键不同请求失败。所有列表按领域时间和稳定 ID/位置排序。

## M5B–D 依赖

- M5B 必须提供 PostgreSQL migration 与事务型 Repository，实现与本文件领域契约一致的 Workspace 隔离、唯一活动调查、幂等冲突、Evidence/Hypothesis 引用完整性和 Outbox 原子提交；Memory 行为不能作为持久化替代。
- M5C 必须在 Temporal/Runner Gateway 边界实现任务领取、lease fencing、重试与取消。Workflow/History 只传 ID 和小型脱敏 receipt；连接器目标由 Gateway 服务端配置解析，不接受 TaskSpec 注入目标或凭据。
- M5D 必须实现模型路由、结构化 Hypothesis 校验、确定性证据报告、人工 Feedback 与离线评测。模型失败和无模型配置不得吞掉 Evidence，也不得升级为生产动作授权。

## 生产写不存在启用路径

M5A1 没有 SQL migration、PostgreSQL 实现、Temporal Workflow、Runner Gateway 路由或 HTTP API；也没有 ActionPlan、策略、审批、执行器或 production-write feature flag 的连接代码。当前分支中的调查仓储不能触发连接器调用或任何生产写操作。后续里程碑在完整策略、审批、短期凭据、隔离 Runner 和执行审计链全部落地前，必须继续保持生产写不可达。
