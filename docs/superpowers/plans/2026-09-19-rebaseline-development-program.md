# 2026-09-19 重新基线开发计划

> 状态：`SPEC_APPROVED / DEVELOPMENT_PAUSED / RUNTIME_CLOSED`
> 审计基线：`origin/main@90c19b7bbeb17381a72e3cd21dd85b10e01767d4`
> 活动 Batch：`NONE`

这是暂停检查点之后的唯一恢复计划。它重新声明远端基线、文档入口、Agent 协作和后继 Batch 顺序；它不实现业务代码、不开放 Provider/Capability/Action，也不把旧分支或未合并 worktree 重新纳入事实。

## 入口与不变量

- 开工前必须读取 `docs/status/current.md`、已确认设计规范、八阶段总计划、快速开发计划、阶段 README、版本基线和相关契约。
- 每个 Batch 从届时最新 `origin/main` 创建独立 worktree，模块根不得包含嵌套 `.worktrees`；不得删除或修改用户已有 worktree。
- `docs/status/current.md` 仍是唯一完成度事实源；OpenAPI、迁移、ADR 和规范的权威性不因本计划改变。
- 测试 fake、memory repository、MSW、loopback transport 只允许在测试路径；生产装配缺依赖必须 fail closed。

## 恢复顺序

| 顺序 | Batch | 责任与出口 |
| ---: | --- | --- |
| 1 | fresh identity-FK fixture corrective | 仅修复已冻结 fixture 合同，真实 RED→GREEN、G1/G2、独立 review、PR/merge。 |
| 2 | Task 19A2a exact-12 | 消费已合并 fixture，完成 Source Gate formal migration/test contract；未通过前不启动。 |
| 3 | post-A2a exact-2 | 只拥有 validation corrective，不能扩展到 Provider runtime。 |
| 4 | Task 19A2b | durable current-trust rechecks；依赖 exact-12 已合并。 |
| 5 | Task 19A2c | 隔离 sealer/admitter connector 与 Task 28A seam；缺 authority/issuer 仍关闭。 |
| 6 | Task 29A | two-worker HA、cleanup、restart、response-loss receipt；不制造 Provider availability。 |
| 7 | Task 19B | CMDB canary/evaluator/AdmitGate operating proof；逐类型门禁。 |
| 8 | Task 29B | 聚合已完成的 per-source gate/canary/HA receipts；仍需 G3/G4。 |

Batch 之间必须满足：前一 Batch 已合并、Produces 稳定、G2 通过、独立复核无未解决阻断；任何漂移、失败或不确定结果都停在最后已验收状态。

## G1–G4 验证

G1 覆盖文档/静态/受影响定向测试；G2 覆盖 Batch 关键行为、数据库/协议契约和必要 race/恢复；G3 覆盖纵向装配、全仓 race、真实恢复、安全与浏览器/E2E；G4 覆盖真实 Provider、HA、非生产资格、生产 Shadow/Canary、SLO/DR、安全与独立签名 release decision。任何低层门通过都不自动通过更高层门。

## 暂停边界

暂停期间只允许审计、文档治理和恢复准备。禁止开始 fixture corrective、Task 19A2a 或任何 Provider/Worker/Capability/Action 实现；禁止把 `BUILT_CLOSED` 解释为 `AVAILABLE`。恢复需要明确的人工恢复信号，并重新确认最新远端 SHA、分支、worktree 和未解决审计项。

## 交付物

每个 Batch 交付原子 commit、文件所有权说明、基线与 diff 摘要、G1/G2 结果、未执行的 G3/G4 证据和能力状态。最终项目只有在独立签名的 `PRODUCTION_CLOSED_LOOP_ACCEPTED` 后才能描述为生产闭环。
