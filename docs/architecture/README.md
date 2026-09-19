# 架构文档入口

本目录是当前架构与 Agent 开发治理的唯一入口。它描述如何从已确认契约、当前状态和实际代码结构推导下一步工作，不替代 `docs/status/current.md`、OpenAPI、数据库迁移、ADR 或阶段任务包。

## 当前入口

- [当前项目状态](../status/current.md)：完成度、暂停状态、能力关闭态和恢复入口的唯一事实源。
- [Agent 开发指南](agent-development-guide.md)：远端基线、worktree、Batch、G1–G4、交接与验证规则。
- [AI Agent 活代码地图](agent-code-map.md)：GitNexus 的确定性结构图、影响分析和新鲜度边界。
- [架构概览](overview.md)：系统上下文、部署单元、事实源和执行信任链。
- [治理运维总计划](../superpowers/plans/2026-07-13-governed-operations-program.md)：八阶段产品范围与出口契约。
- [重新基线开发计划](../superpowers/plans/2026-09-19-rebaseline-development-program.md)：当前暂停后的恢复门、Batch 顺序和交付证据。

## 文档层级

`docs/status/current.md` 负责“现在是什么状态”；规范、ADR、V4 架构、迁移与 OpenAPI 负责“必须是什么”；代码地图只负责“当前 worktree 实际有什么结构”。历史蓝图和 2026-07-10/11 旧计划保留决策证据，但不是当前执行入口。

任何文档与状态源或已验收契约冲突时，应先停止实现并修正文档契约。暂停期间不得以局部测试、旧分支、脏 worktree、快照或未合并 PR 推高完成度或开启能力。
