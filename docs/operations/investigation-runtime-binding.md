# Investigation runtime binding 运维契约

日期：2026-07-11
范围：`000013_investigation_runtime_binding`、`investigation.create.v2`、READ claim/complete v2 wire

## 安全目标

新 Investigation 必须在一个 Repository 原子边界内固定完整 PlanBinding，并为每个 canonical READ Task 固定 connector、target、executor 与 aggregate runtime digest。Binder 不能提供 aggregate digest 或绑定时间；Repository 使用锁定的 Incident scope、Task position/input hash 和可信 component digest 自行计算。数据库随后把同一 Plan/Runtime 快照复制到 Attempt 与 `runner-evidence.v3` Receipt，Runner 请求不能提交或覆盖这些事实。

迁移后的 insert-only 数据库守卫同时拒绝新 create.v1 Investigation、未绑定 runtime Task 和 create.v1 ledger，避免旧写入者在 cutover 后制造新遗留事实。READ Descriptor/Gateway 还会按持久 Tenant/Workspace/Environment/Service、MappingExact、Task 与 component digest 独立重算 aggregate RuntimeDigest，并验证 ConnectorID 的内容地址后缀；仅有“格式正确”的自选摘要不能进入 Claim。

历史 `investigation.create.v1`、未绑定 Task、legacy Attempt 及 `runner-evidence.v1/v2` 保持原样可查询，不做回填，也不能进入新 claim 路径。精确同键 create.v2 重放在 mutable authorizer/binder 之前返回原事实；新 key 绑定活动 Investigation 必须重新运行两层准入并逐 Task 比对全部摘要。

## 发布顺序

1. 保持 READ claims 与所有 WRITE claims 关闭；停止并 drain 旧 READ Runner、Gateway 写事务、Worker 和调查 Repository 写入者。
2. 确认没有 `LEASED/RUNNING` READ attempt，也没有 `QUEUED/RUNNING` create.v1/unbound Investigation。
3. 以受控迁移角色应用 `000013_investigation_runtime_binding.up.sql`。迁移使用 5 秒 `lock_timeout` 和确定顺序的 `ACCESS EXCLUSIVE` 锁；锁超时或 cutover guard 失败即中止发布，不重试为部分成功。
4. 部署理解 create.v2、完整 binding、Attempt hash-version v3 与 Receipt v3 的 Control Plane/Gateway 代码。禁止旧、新 READ 写入者混跑。
5. 保持关闭态 Admission，先验证查询、create/replay、未绑定 Task 拒绝和数据库告警；C2-4a Bundle 已完成本地契约，但真实 C2-4b/4c assembly 及外部 PKI/network/E2E 门禁完成前不得开启 claim。

## 验证查询

发布后应满足：

- 新 Investigation 的五个 `plan_*` 字段完整，`request_hash_version = 'investigation.create.v2'`；
- 新 Task 的六个 runtime 字段完整，`runtime_bound_at = created_at`，ConnectorID 后缀等于 `connector_digest`；
- 非终态新 Attempt 的两个 hash-version 为 NULL，`COMPLETED` Attempt 精确为两个 v3 version；
- 新 Receipt 只使用 `runner-evidence.v3`，并通过包含 Plan/Runtime 与 hash-version 的完整 Attempt fence；
- 未绑定 Task claim 在 TokenSource 调用前返回不可领取结果。
- Descriptor 中 ConnectorID 后缀必须等于 ConnectorDigest，aggregate RuntimeDigest 必须由完整持久 scope、Task 和 component facts 重算一致。

不得把 fake/本地契约测试记录为真实 PKI、Vault、Temporal HA 或企业数据源验收证据。

## 回滚

只有纯 legacy 数据集才能应用 down migration。存在任一 create.v2 ledger、Plan/Runtime binding、Attempt hash-version、v3 Receipt 或活动 Attempt 时，down 必须以 SQLSTATE `55000` 拒绝；不得删除、置空或伪造这些事实来强行回滚。

若 up 已成功但新二进制尚未启动，可在确认没有任何新绑定事实后执行 down，并恢复旧二进制。若已产生新绑定事实，只能前向修复；继续保持 claims disabled，保留新 schema 与兼容二进制。

## 本阶段未开放能力

- 不新增 Runner 路由，请求 schema 仍为 v1，Runner 不能提交 digest；
- 不修改 `cmd/*`、配置、dispatcher 或 claim assembly；
- 不解析 endpoint、CA、credential ref 或 Secret；
- 不提供生产写开关，`AIOPS_WRITE_EXECUTION_MODE` 的既有 `disabled|non-production` 边界不变。
