# AI Agent 活代码地图治理规范

> 状态：工程治理规范；不改变产品实现状态或阶段入口门
> 生效日期：2026-07-14
> 工具基线：Node.js 24、pnpm 10.34.0、GitNexus 1.6.9

## 1. 目的与边界

本规范为人类和 AI Agent 提供同一套“先确认权威契约，再理解实际代码，再评估变更影响”的导航流程，降低模块多、并行 worktree 多和跨阶段实现时的误读风险。代码地图必须随检出提交和未提交差异更新，但它是可重建的派生证据，不是新的产品、架构或完成度事实源。

以下内容仍分别拥有唯一事实地位：

- [当前项目状态](../status/current.md) 是完成度、阶段状态和是否已实现的唯一事实源。
- [已确认设计规范](../superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md)、已验收 ADR、当前/未来 V4 架构和[八阶段总计划](../superpowers/plans/2026-07-13-governed-operations-program.md)定义意图、边界和实施顺序。
- `api/openapi/control-plane-v1.yaml` 是公共 API 唯一契约；迁移文件拥有数据库结构；生成类型不得成为反向事实源。
- GitNexus 只回答当前 worktree 中“代码实际上有什么结构关系、调用链和变更影响”，不能证明能力已上线、Provider 已可用、生产门已开放或运行时行为一定正确。

代码地图不授权跳过必读文档、任务包 checkbox、TDD、契约测试、安全检查、人工审查或阶段验收。地图与权威契约冲突时，按项目指令停止实现：先判断是实现漂移、地图过期还是规范冲突，不能选择较宽松解释。

## 2. 分层事实模型

| 层级 | 回答的问题 | 所有者与载体 | 更新方式 | 可否作为发布真值 |
|---|---|---|---|---:|
| L0 完成度 | 现在做到哪里、哪些能力已验收 | `docs/status/current.md` | 阶段验收后人工审查更新 | 是 |
| L1 预期架构 | 系统应当如何组织、边界和契约是什么 | 规范、已验收 ADR、V4、总计划、OpenAPI、迁移 | 受控文档/契约变更 | 是 |
| L2 实际结构 | 当前检出代码如何依赖、调用和聚类 | GitNexus AST/符号/调用图，绑定 worktree、HEAD 和 diff | 本地重建，CI 每次重建 | 仅作结构证据 |
| L3 辅助解释 | 如何更直观地讲解或探索复杂关系 | C4/Structurizr 视图、Graphify 或 LLM 生成的语义图 | 人工审查或按需生成 | 否，除非内容已回写并通过 L1 审查 |

采用 C4 的视角分工，但不复制事实：System Context、Container、Component 由 L1 中的 V4/ADR 维护，Code 级依赖和执行流由 L2 自动生成。一个图可以链接权威对象，不得另写一份会独立漂移的服务、API、数据表或发布状态清单。

## 3. 确定性结构图基线

GitNexus 1.6.9 是本仓库唯一门禁级代码地图工具，必须通过仓库包装脚本以固定版本运行：

```bash
scripts/code-map.sh status
scripts/code-map.sh refresh
scripts/code-map.sh modules 20
scripts/code-map.sh processes 20
scripts/code-map.sh query '<concept>' '[task context]'
scripts/code-map.sh context '<symbol>'
scripts/code-map.sh impact '<symbol>'
scripts/code-map.sh changes all
scripts/code-map.sh verify
scripts/code-map.sh snapshot '<output-dir>'
```

约束如下：

- 禁止使用 `gitnexus@latest`、未固定的全局命令或不同 Agent 各自选择工具版本。
- GitNexus 1.6.9 使用 `PolyForm-Noncommercial-1.0.0`；商业、收费或客户交付场景启用本地/CI 门禁前必须取得适用的商业许可，或经独立复核替换为许可证兼容工具，开发依赖不进入产品镜像不代表可以忽略许可证。
- GitNexus 及全部传递依赖由 `tools/code-map/package.json` 和 `tools/code-map/pnpm-lock.yaml` 锁定；本地和 CI 只允许 `pnpm install --frozen-lockfile` 后执行，`pnpm dlx` 仅用于前期研究，不是本仓库运行路径。
- Codex/IDE 的 ambient GitNexus MCP 只有在版本等于 1.6.9、仓库路径等于当前 worktree 且资源可读时才可作为同一派生图的查询入口；版本漂移、空 clusters/processes 或路径不符时必须回退到仓库脚本，不能把旧 MCP 结果当作当前地图。
- `refresh` 必须使用 `analyze --skip-agents-md --no-stats`；GitNexus 不得生成、覆盖或补写 `AGENTS.md`、Skill 或权威架构文档。
- 默认关闭 embeddings 和外部语义服务。门禁只使用本地可重建的解析、符号、依赖、调用链、进程和 git diff 映射。
- `.gitnexus/` 是当前 worktree 的派生缓存，必须保持未跟踪；不得提交数据库、机器绝对路径、时间戳或易变统计。
- `.gitnexusignore` 必须排除包含真实 Secret/凭据值的本地文件、构建产物、依赖缓存、覆盖率/测试报告、二进制、大型数据样本和生成式可视化输出。忽略规则不能用来隐藏凭据治理代码、受治理的生产源文件或测试。
- 包装脚本必须在依赖安装前执行高置信凭据与 Secret-like 文件预检，以扩展名无关的结构解析识别可解码 PEM/OpenSSH/PGP/PPK/age/minisign 私钥材料，并把扫描器内部错误视为失败；测试中的 Token canary 只能按精确文件与值摘要进入最小 allowlist，路径或值变化必须重新审查。扫描、文件类型检查与指纹使用同一输入集合：全部 tracked 文件，加上只按仓库根 `.gitignore`/`.gitnexusignore` 排除的 untracked 文件；不得递归采用子目录 ignore，也不得让 `.git/info/exclude`、用户全局 ignore、ambient `GITNEXUS_NO_GITIGNORE`、`assume-unchanged` 或 `skip-worktree` 隐藏实际建图输入。以完整工作树原始字节指纹包住 frozen-lockfile 安装并在安装后再次预检，依赖安装不得改变输入。安装、解析、查询和结构检查都必须由 Node 24 deadline runner 建立独立子进程组，默认 600 秒截止、TERM 后 10 秒 KILL，并在父进程提前退出时仍清理同组后代；仅可在 30–1800 秒范围通过 `AIOPS_CODE_MAP_COMMAND_TIMEOUT_SECONDS` 调整单命令期限。建图使用 `umask 077`；原始 `.gitnexus/` 含源码片段和路径，禁止作为 CI artifact 上传，CI 只允许发布裁剪后的计数、版本、commit 和结构检查结果。
- CI 生成的 snapshot/artifact 必须绑定准确 commit SHA，只用于审查和诊断；下一个提交必须重新生成，不能把旧 artifact 当成当前分支地图。
- `snapshot` 的目标路径必须尚不存在；worktree 内只允许写入专用且已忽略的 `.code-map-artifact/` 子目录，其余目标必须位于当前 worktree 外，禁止把目标或 staging 放进 `.gitnexus/` 或任一操作锁。脚本只在解析后的同级 `0700` staging 目录写入固定白名单文件，全部查询、结构检查与读后新鲜度复核成功后才以 rename 原子发布，普通失败不会留下貌似完整的目标 artifact。

Graphify、LLM 总结和自然语言推断可以作为人工探索或演示视图，但不得进入 merge/release gate，不得覆盖确定性边，也不得声称推断关系已经实现。需要把语义发现变为架构事实时，必须回写对应 ADR/V4/OpenAPI/任务包并单独复核。

## 4. 每个 Agent 的强制导航流程

### 4.1 开工前

1. 按 `AGENTS.md` 顺序读取状态、规范、总计划、覆盖矩阵、版本基线、当前阶段索引和任务包。
2. 在自己实际修改代码的 worktree 根运行 `scripts/code-map.sh status`，只把输出用于观察索引是否存在和绑定哪个 HEAD；GitNexus status 不感知全部未提交变化，不能单独证明新鲜。
3. 每次开工都运行增量 `scripts/code-map.sh refresh`；索引缺失时会创建，已有索引则映射当前 worktree 内容。刷新失败不得依赖旧图继续跨模块修改。
4. 对任务概念运行 `query`，再对返回的核心符号运行 `context`。只看目录名或单一命中不足以确认调用链。
5. 用 `rg`、源文件、测试和权威契约核对地图结论；地图没有解析到的反射、代码生成、配置装配、SQL、Helm 或外部协议关系必须人工补查。

### 4.2 修改前

1. 对拟修改的入口、接口、构造函数、Repository、Runner/Worker 装配或共享前端 primitive 运行 `impact`；`UNKNOWN`、partial、truncated、lower-bound 或非 `exact` 结果一律不得当成完整影响面。
2. 同时检查 upstream dependants、downstream dependencies 和相关测试；跨阶段接口还必须核对 `Produces/Consumes`、OpenAPI、迁移和 ADR。
3. 影响到三个及以上模块、生产装配、安全边界、公共契约或未知动态边时，在实施计划或审查说明中记录受影响面和验证命令。
4. 图与代码不一致、关键语言不受支持或影响结果为空但人工检索发现依赖时，将地图视为不完整证据并 fail closed：扩大人工检索与测试范围，修复自动化后才能以地图通过门禁。

### 4.3 修改后

1. 对未提交或 staged diff 运行 `scripts/code-map.sh changes all`，核对被改变的符号、执行流和测试面。全部 scope 都在同一个 locked fresh read 内检查闭包并计算文件数，同时由包含 index mode/OID/path 的工作树指纹做读后复核；全部 scope 都拒绝可索引的 untracked 输入，`unstaged` 还要求 index 无 staged 变化，`staged` 要求 tracked 工作树无 unstaged 变化，`compare` 要求 tracked 工作树和 index 都干净，避免用包含 scope 外内容的图解释局部 diff。包装脚本必须读取原始结构化结果并拒绝 error、partial、truncated、unknown、文件计数遗漏和非空 diff 的零符号结果；先人工确认并 stage 本次有意新增的文件，再重新运行。删除、纯重命名、复制、类型变化或冲突状态同样 fail closed，必须对旧/新路径做人工影响分析，不得用遗漏变更的低风险结果交付。
2. 代码、契约、迁移、构建或运行装配发生变化后运行 `refresh`；纯文字修订可以不重建 AST 图，但仍需通过文档验收。
3. 运行 `verify`，确认固定版本重建成功、索引属于当前 worktree/HEAD 且 `AGENTS.md` 未被工具改写；CI 或审查取证再以 `snapshot` 生成 commit-bound 派生 artifact。
4. 地图检查永远不能替代任务包指定的 Go/PostgreSQL/OpenAPI/Web/E2E/安全/恢复验证；二者任一失败都不能交付。
5. 交付说明只报告地图覆盖到的结构事实和已运行验证，不把“索引成功”描述成“实现完成”或“生产可用”。

## 5. 并行 worktree 与并发会话

- 每个 worktree 在自己的根目录建立独立 `.gitnexus/`；禁止多个 worktree 共享、复制或软链接同一索引。
- Agent 只能刷新自己被授权修改的 worktree。索引其他会话的脏 worktree前必须先取得其所有者同意，且不得运行会写入其 `AGENTS.md` 或配置的命令。
- 代码地图的身份至少绑定 repository root、worktree root 和 HEAD；同名分支或相同仓库 basename 不能证明是同一索引。
- 合并、rebase、cherry-pick 或切换基线后，旧 worktree 地图立即视为 stale，必须重建后再进行影响判断。
- 包装脚本在 `modules/processes/query/context/impact/changes/snapshot` 前先核验工作树内容指纹；指纹或 HEAD 变化时自动执行增量 refresh，并在同一 map operation lock 内完成绑定复核、数据库读取和读后指纹复核；代码在读取期间变化时丢弃结果并 fail closed。
- 每个命令先使用 Linux `flock` 或 macOS `lockf` 持有整个进程生命周期的 `.gitnexus-operation.lock`；内层 map operation lock 再串行化同一 worktree 的 graph reader/writer，先在 owner-only pending 目录写齐 PID、主机、以 `LC_ALL=C/TZ=UTC` 归一化的进程启动时间和随机 nonce，完成 exact-entry 验证后再以 rename 原子发布。OS advisory lock 使 stale-lock 判断与回收本身也保持串行；同主机且已确认 owner 消失或 PID 被复用时才自动回收，活锁、跨主机锁或元数据不完整的锁一律拒绝盲删并要求人工核对。
- tracked/untracked 索引输入、`.gitnexus/`、OS lock 文件和内层锁目录必须是当前用户拥有的 worktree 内真实普通文件/目录；普通文件链接计数必须为 1，`.gitnexus/` 与锁路径还必须保持 owner-only 权限，禁止 symlink、hardlink 或其他特殊文件。worktree 指纹只能先写入 `.gitnexus/` 内 owner-only 临时文件，再以平台对应的 rename 原子发布并复核全工作树未漂移。该约束避免跟随链接读取工作树外内容、在 FD open 前阻塞于 FIFO、通过 hardlink 截断外部文件，或在 stale-lock 清理时触碰外部路径。
- 其他会话的进展以其提交和 `docs/status/current.md` 为准。代码地图只能帮助发现重叠文件和调用影响，不能自动解决未提交冲突，也不能覆盖另一会话的状态更新。

## 6. 自动更新与 CI 门禁

仓库以本地包装脚本和 `.github/workflows/code-map.yml` 自动化派生地图：

```text
checkout exact SHA
  -> Node 24 + pnpm 10.34.0
  -> high-confidence secret preflight + worktree fingerprint
  -> frozen tools/code-map/pnpm-lock.yaml install + post-install fingerprint
  -> GitNexus 1.6.9 deterministic refresh
  -> verify guarded files unchanged
  -> validate worktree/HEAD binding, zero embeddings and graph cycles
  -> produce commit-bound snapshot artifact
```

门禁要求：

- Pull Request 和主干提交都从干净 checkout 重建，不信任开发机上传的 `.gitnexus/`。
- Workflow 的第三方 GitHub Actions 必须固定到已核验 commit SHA，并在行尾保留可读 major 注释；不得只依赖可移动 tag。
- Secret 预检、frozen-lockfile 安装、安装前后工作树完整性、解析、索引完整性、零 embeddings、循环依赖检查、受保护文件漂移、CI 干净树复核或 snapshot 生成任一失败，代码地图检查失败；检测到既有 embeddings 时必须带 `--drop-embeddings` 全量重建，固定配置和 metadata 继续验证为零；增量索引损坏时只允许一次全量重建自愈，全量仍失败则不得降级成旧图或 warning。
- CI 不自动提交生成索引、不自动修改架构文档，也不使用 bot 循环提交“地图更新”。这样可以避免派生文件与源代码竞争主干。
- 当前 workflow 对每次 Pull Request、push 和手工触发都重建；未来如需跳过纯文档变更，必须以可审计 path filter 单独复核，一旦触及源代码、测试、OpenAPI、迁移、Helm、Dockerfile、依赖锁或构建配置仍必须重建。
- snapshot 只保留安全的文件/节点/关系/模块/流程计数、结构检查和工具元数据，不包含源码正文、符号详情、Secret、环境变量值、凭据、构建日志中的敏感值或机器绝对路径；发布前后都必须验证恰好七个 owner-only、单链接普通文件，并解析 manifest、计数 JSON 与 `cycleCount=0` 的结构 schema。CI artifact 逐文件列出同一白名单，禁止上传整个目录兜底。

## 7. 新鲜度与关闭条件

本地导航地图只有同时满足以下条件才是 `FRESH`：

- 使用 [版本基线](../superpowers/plans/2026-07-13-governed-operations/version-baseline.md)固定的工具链和已提交 lockfile；
- 索引根目录等于当前 worktree 根，且绑定当前 HEAD；
- 当前 diff 已经由 `changes` 映射，或代码变更后已经完成 refresh；
- 受保护的 `AGENTS.md`、规范和权威契约未被生成器改写；

提交进入审查或交付时，还必须由 CI 在 exact SHA 上成功重建并产出 commit-bound snapshot，才是可接受的交付地图；未提交 worktree 无法用旧 CI artifact 证明新鲜度。

以下任一情况视为 `STALE/UNKNOWN`：切换提交或分支、合并其他会话更新、存在未映射代码 diff、工具版本漂移、解析失败、索引跨 worktree 复用、受保护文件被生成器改变、CI snapshot 对应其他 SHA。对跨模块、公共契约、生产装配或安全边界的修改，`STALE/UNKNOWN` 必须阻断交付；先刷新或使用源文件/`rg`/测试完成可审计的人工影响分析并修复地图链路。

## 8. 维护责任与验收

任何代码地图基础设施变更必须同时验证：

```bash
scripts/code-map.sh verify
git diff --check
git status --short
```

审查者还需确认：固定版本无 `latest`、`.gitnexus/` 未被跟踪、每个 worktree 独立、Secret/构建产物被排除、工具未改写 `AGENTS.md`、CI artifact 绑定 commit、语义图没有进入发布门。若 GitNexus 升级，先更新版本基线和包装脚本，再在代表性 Go/TypeScript/SQL/Helm 变更上验证兼容性；不能静默漂移。

行业参考：

- [C4 model](https://c4model.com/)：用分层视图区分系统、容器、组件与代码。
- [Structurizr documentation](https://docs.structurizr.com/)：以可版本化模型生成一致视图。
- [GitNexus](https://github.com/abhigyanpatwari/GitNexus)：本地代码知识图、调用/影响分析和 MCP/CLI 工作流。
- [GitHub repository custom instructions](https://docs.github.com/en/copilot/how-tos/configure-custom-instructions-in-your-ide/add-repository-instructions-in-your-ide)：仓库级与路径级 Agent 指令的发现和优先级。
