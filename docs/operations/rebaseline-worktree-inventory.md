# 重新基线 Worktree 与分支审计记录

> 审计日期：2026-09-19
> 审计仓库：`aiops-system`
> 精确远端基线：`origin/main@90c19b7bbeb17381a72e3cd21dd85b10e01767d4`
> 本报告用途：记录审计方法与暂停期间的保护事实；不删除、归档或修改任何 worktree。

## 审计方法

在文档 Batch 的隔离 worktree 中执行以下只读命令，并把输出与当前 commit 一起保存到交接记录：

```bash
git rev-parse HEAD
git status --short --branch
git remote -v
git worktree list --porcelain
git for-each-ref --format='%(refname:short) %(objectname) %(upstream:short)' refs/heads refs/remotes/origin
git log --all --oneline --decorate -12
```

审计时按 `worktree` 记录路径、HEAD、是否 detached、关联 branch；按本地 branch 与 `origin/*` 分开统计。不能用分支名推断实现是否合并，也不能把 detached snapshot、dirty WIP、已停止 A2a 或其他 Agent 的未提交内容当作契约、ABI 或验收证据。

## 本次事实

- 当前文档审计 worktree 为 `/Users/seaxu/.codex/worktrees/rebaseline-docs/8-ai-ops-system`，detached HEAD 为 `90c19b7bbeb17381a72e3cd21dd85b10e01767d4`，工作区干净。
- `origin/main` 与 `origin/HEAD` 均指向 `90c19b7bbeb17381a72e3cd21dd85b10e01767d4`；远端只作为当前执行基线，历史 PR/业务 SHA 仍由 `docs/status/current.md` 追溯。
- 本次 `git worktree list --porcelain` 观察到 **107 个 worktree**，`git for-each-ref` 观察到 **164 个本地 branch ref** 和 **3 个 origin remote refs**。计数是审计时快照，后续会随 Agent 生命周期变化，不能作为完成度指标。
- 交接审计快照同时记录了 manager 在同一轮重基线盘点中的 **104 个 worktree、162 个本地 branch、138 个无对应 worktree 的 branch、6 个 dirty worktree**。本隔离 worktree 的只读复核稍后观察到 107/164，说明 Agent 生命周期会在盘点间改变计数；两组数字都只证明盘点时事实，不能作为完成度或删除依据。
- 已知并行 worktree 包括 `rebaseline-code`、`rebaseline-development`、本报告所在的 `rebaseline-docs`，以及大量 `codex/*` 实现/状态 worktree；主工作区 `/Volumes/SX-990-PRO-2T/develop/8-ai-ops-system` 及其嵌套 `.worktrees/` 属于用户/历史工作资料，必须保留。
- 发现的 detached worktree、旧 `codex/*` 分支、停止的 A2a worktree/WIP/snapshot/review 仅可作为审计对象。它们不得被 cherry-pick、rebase、复制或用作恢复祖先；恢复必须重新从届时最新 `origin/main` 创建 fresh worktree。
- 当前状态仍为 `SPEC_APPROVED / DEVELOPMENT_PAUSED / RUNTIME_CLOSED`，活动 Batch=`NONE`。任何 worktree 数量、分支数量、CI 绿灯或本地测试通过都不会解除暂停或开启运行能力。

重新基线 maintenance 只表示对入口、状态、历史标记和交接证据进行治理；它不等于恢复产品开发，不会开启 Provider、Worker、Capability、Action、运行时或生产写入。

## 保护规则

1. 只读审计可列出和比较 worktree；不得 `git worktree remove`、`git branch -D`、`git clean`、覆盖用户文件或清理嵌套 `.worktrees`。
2. 文档 Batch 只能在自身隔离 worktree 修改已分配文档；发现其他 worktree 有脏改动时记录事实并绕开，不以删除脏内容制造绿灯。
3. 交付前再次运行 `git status --short --branch` 与 `git diff --check`，确认只包含本 Batch 的文档变更；合并后由主 Agent 重新审计最新 `origin/main`。
4. 暂停恢复时重新执行本节全部命令，更新基线、计数和保护清单；旧报告只保留历史审计证据。
