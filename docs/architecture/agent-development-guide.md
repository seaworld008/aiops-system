# Agent 开发指南

> 当前治理基线：`origin/main@90c19b7bbeb17381a72e3cd21dd85b10e01767d4`（2026-09-19 审计）。
> 当前状态：`SPEC_APPROVED / DEVELOPMENT_PAUSED / RUNTIME_CLOSED`；活动 Batch 为 `NONE`。

本指南把一次 Agent 工作限定在可审计的隔离 worktree、稳定接口和分层验证内。它不授权修改业务范围，也不把模型、分支或测试假设当作事实源。

## 开工顺序

1. 从最新 `origin/main` 读取 `docs/status/current.md`，确认状态仍为 `DEVELOPMENT_PAUSED / RUNTIME_CLOSED`。
2. 依次读取已确认设计规范、八阶段总计划、快速开发计划、阶段索引、版本基线和相关 ADR/Runbook/OpenAPI。
3. 审计 `git status`、`git worktree list`、分支和远端 head；禁止删除、清理或覆盖用户 worktree。
4. 在实际 worktree 根运行 `scripts/code-map.sh status` 与 `refresh`。纯文档 Batch 可记录人工影响分析，但不得把旧索引当作代码事实。
5. 明确文件所有权、Produces/Consumes、暂停边界和本 Batch 的验证命令，再开始编辑。

## Batch 与协作

一个 Batch 聚合 2–4 个相关旧 Task，文件所有权必须不重叠。每个 Agent 只修改分配的文件，交接内容至少包含基线 SHA、文件清单、状态变化、验证结果和未解决阻塞。后继 Batch 只消费已合并的稳定 `Produces`，不能读取其他 worktree 的未提交实现、测试产物或快照。

Batch 结束前应运行 `git diff --check`、文档链接/Markdown 检查、Secret/占位标记检查，以及必要的代码地图 `changes all`/`verify`。文档 Batch 不得顺手修改 Go、Web、迁移、CI 或生成类型。

## G1–G4 门

| 门 | 用途 | 证据边界 |
| --- | --- | --- |
| G1 | 快速门 | 格式、静态契约、受影响定向测试和本地最小验证；不证明生产可用。 |
| G2 | Batch 门 | Batch 内关键行为、数据库/协议契约、race 或恢复证据；只证明该 Batch 的稳定接口。 |
| G3 | 纵向 Milestone 门 | 真实装配、跨模块、全仓 race、恢复、安全和浏览器/E2E 证据。 |
| G4 | 资格与发布门 | 真实 Provider、HA、生产影子/Canary、SLO/DR、安全和独立签名 release decision。 |

未通过 G4 前，Provider、Capability、Action 和运行路径必须保持 `NOT_STARTED / UNAVAILABLE / CLOSED` 或 `BUILT_CLOSED`；任何 CI 绿灯、静态图或文档完成都不能改写这个状态。

## 当前暂停与恢复

当前暂停是有意的治理状态，不得自行恢复。恢复必须从届时最新 `origin/main` 创建全新、独立且不含嵌套 `.worktrees` 的 worktree，由人工明确恢复后，按以下顺序执行：

```text
fresh test-only identity-FK fixture corrective
  -> fresh Task 19A2a exact-12
  -> post-A2a exact-2 validation corrective
  -> Task 19A2b
  -> Task 19A2c
  -> Task 29A
  -> Task 19B
  -> Task 29B
```

每一步都必须真实 RED→GREEN、完成该步 G1/G2、独立复核并合并后，下一步才能创建。停止的 A2a、旧 WIP、dirty worktree、snapshot 和 review 不能成为祖先、输入、ABI 或验收证据。恢复后的实现仍不自动开启运行能力；G3/G4 和逐类型 Go/No-Go 另行门禁。

## 交付说明

交付必须报告实际基线与提交 SHA、改动文件、G1–G4 中已通过的门、未通过或 deferred 的门，以及能力状态。不要把历史证据、设计完成、测试通过或代码地图新鲜度写成生产上线。
