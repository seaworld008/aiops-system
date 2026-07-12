# Investigation READ 结果恢复运维契约

日期：2026-07-11
范围：M5C2-2 DB-only result recovery 与未注册的 Temporal Activity

## 目标与信任边界

当 Runner 已提交完成事务，但 Gateway 响应、Activity 返回值或 Worker 进程随后丢失时，Workflow 不能重放原完成正文，也不能依赖旧 bearer、mTLS 连接或原 Runner 实例。恢复必须仅使用当前 schema 中已经提交的不可变事实，确定同一 READ Task 是仍在进行、已提交终态，还是被 Control Plane 取消。

恢复 Repository 是可信 Control Plane/Temporal 的只读依赖，不是 Runner Gateway route。调用方只能提供既有 History 中的 Tenant、Workspace、Incident、Investigation、Task、position 与四个 Plan digest；Tenant 只用于与 Workspace 派生的持久 Tenant 比较，不能作为跨 Workspace 选择器或响应字段。接口不接收 completion body、bearer、Runner ID、证书、scope revision、TargetRef、credential 或任意 hash 覆盖值。

## 数据证明链

每次恢复都开启 PostgreSQL `READ ONLY` 事务，且 Repository 不持有 TokenSource、IDSource 或任何写入口：

1. 以 Workspace、Investigation、Task、Incident、position 和完整 `investigation-plan-manifest.v1` binding 读取 v2/bound Task，并从 Workspace 关联得到持久 Tenant。
2. 对 `QUEUED/RUNNING` Task 返回 `PENDING`，不猜测最终结果。
3. 对 `EVIDENCE/FAILED/CANCELLED` Task 读取该 Task 的唯一 Receipt；`EVIDENCE/FAILED` 缺少 Receipt 是完整性故障，`CANCELLED` 缺少 Receipt 表示 `CONTROL_CANCELLED`。
4. 使用 Receipt 自身的 lease epoch 精确读取 Attempt，禁止选择“最新”或最大 epoch。
5. 重新验证 Task、Attempt 与 `runner-evidence.v3` Receipt 的完整 PlanBinding、RuntimeBinding、Runner、scope revision、证书指纹、idempotency key、request/receipt hash 与版本，以及 Evidence/失败/取消 union。
6. 只返回 Task 状态和必要的 Evidence ID/content hash；Receipt ID/hash 仅在 Repository 内部安全投影中用于完整性验证，不进入 Activity 输出。

恢复不重新检查历史 Runner 或证书当前是否 enabled/revoked。它们已经作为完成时的不可变身份快照参与 Receipt 证明；把当前注册状态加入恢复授权会使已提交事实因后续正常轮换而不可读。

## 状态与 Temporal 错误

| 恢复状态 | 含义 | Workflow 处理 |
| --- | --- | --- |
| `PENDING` | Task 仍为 `QUEUED/RUNNING`，尚无可证明终态 | 后续 v2 Workflow 按受控策略等待/重试，不重复提交不确定正文 |
| `COMMITTED` | v3 Receipt 与指定 epoch 的 completed Attempt 完整匹配 | 使用 Task 状态；Evidence 仅返回 ID/hash |
| `CONTROL_CANCELLED` | Task 被服务端取消且不存在 Runner Receipt | 作为确定性取消处理 |

Activity 的无效输入、not found、持久事实完整性漂移和无效 Repository 结果使用固定 non-retryable Temporal error type；数据库不可用、未知依赖错误与已恢复的 panic 使用固定 retryable dependency error。`context.Canceled` 与 `context.DeadlineExceeded` 保留取消语义。底层 SQL、endpoint、credential、请求 ID、Task 输入和 canary 文本不得出现在 error message、Activity output 或 Workflow History。

## 发布与验证

M5C2-2 没有迁移、HTTP route 或 live assembly。部署本变更不会打开 READ claims：

- `cmd/control-plane` 必须继续安装 disabled READ claim/start/complete callbacks；
- preparation Workflow v1 与现有 Worker 注册保持不变；
- 新 Recovery Activity 在 M5C2-4b 的版本化 Workflow 与 task queue 设计落地前不得注册；
- 使用真实 PostgreSQL 16 验证完成后无需 completion body、bearer 或 enabled Runner 即可恢复同一 Evidence ID/hash，并验证 Attempt/Receipt/Evidence 行数完全不变；
- 使用 Temporal testsuite 验证严格 DTO、错误分类、panic 恢复和 History canary 不泄漏。

M5C2-4b 已按该边界完成编排：对一次逻辑 Task 最多发起三个单次尝试的 Runner Activity round；每次之后都调用 DB-only Recovery Activity。只有恢复返回可验证 `COMMITTED` 或 `CONTROL_CANCELLED` 才向 Workflow 投影终态；返回 `PENDING` 时不得把未知远端结果伪装为失败或重新提交同一正文。完整协议见 [Temporal READ orchestration](temporal-read-orchestration.md)。

## 回滚与未开放能力

本阶段仅增加不被 live runtime 引用的代码，可通过回滚应用二进制移除；数据库无需 down migration，已提交 Task/Attempt/Receipt/Evidence 不受影响。若发现恢复完整性错误，保持 READ claims 关闭并前向修复，不得跳过 Receipt/Attempt 验证或从 Runner 重取敏感正文。

本阶段不新增 Gateway route、迁移、配置、`cmd/*`、Activity 注册、Temporal v2 Workflow、target manifest 或固定 executor；也不改变 `AIOPS_WRITE_EXECUTION_MODE=disabled|non-production`，生产写继续不存在启用路径。
