# Governed Operations 快速开发与真实验收计划

> 状态：`APPROVED_EXECUTION_POLICY`
> 日期：2026-07-15
> 适用范围：`docs/superpowers/plans/2026-07-13-governed-operations/` 下的 8 个阶段、59 个任务包、189 个实施 Task
> 目标：在不打开未验收能力、不弱化产品安全契约的前提下，先快速完成系统代码，再集中进入真实集成、HA、安全、恢复和生产资格测试

## 1. 权威关系

本文件是 Governed Operations Program 的**实施节奏与验证分层覆盖层**。它只替换旧计划中的以下规则：

- 全阶段严格串行；
- 每个小 Task 都必须在合并前完成发布级验证；
- 每个 Task 都必须先有完整 RED、再单独提交测试和实现；
- 每次交付都重跑全量 PostgreSQL、race、恢复、E2E、安全和独立复核；
- 后一阶段的关闭态代码必须等待前一阶段全部 Provider 生产验收。

以下事实不被本文件修改：

- 已确认的产品、安全、前端和生产闭环设计；
- `000015`–`000022` 的迁移所有权和顺序；
- 公共 OpenAPI、生成类型、Opaque Credential、Runner Realm、READ/WRITE 隔离和所有 fail-closed 边界；
- 每种 Provider、Capability、Action 的独立生产门；
- 未经资格测试的能力必须保持 `NOT_STARTED / UNAVAILABLE / CLOSED`；
- 只有 `PRODUCTION_CLOSED_LOOP_ACCEPTED` 才能表示完整生产闭环。

发生冲突时按以下优先级处理：

1. 已确认设计规范、已验收 ADR 和核心安全不变量；
2. 本快速开发与真实验收计划；
3. Governed Operations 总计划的产品范围、接口和迁移所有权；
4. 阶段 README 与任务包中的旧执行顺序、逐 Task TDD/验证频率。

任务包中的 Files、Interfaces、Consumes、Produces、错误语义、生产门和最终验收证据仍然有效。旧的逐步 RED/GREEN/commit 指令在快速构建期改为实施参考；真实资格测试期按本文件重新聚合验证，不要求为已经实现的低风险代码伪造历史 RED。

## 2. 为什么需要调整

现行规划共有 189 个 Task、1119 个 Step，平均每个 Task 约 5.9 个 Step。计划文本包含约 476 处 `go test`、158 处 race、569 处 PostgreSQL、137 处独立复核和 296 处恢复相关要求。Task 1 实际跨迁移、角色、ACL、准入、并发、恢复和双实例证明，已经是 Epic，却按单一 Task 执行。

主要浪费来自：

- 在公共接口尚未稳定时追求测试矩阵完美，导致测试本身反复审查和返工；
- 一个局部枚举或定义变化触发与影响面无关的双实例恢复、全量 race 和完整安全复核；
- Provider 广度阻塞后续核心闭环，必须完成所有 Phase 1 Provider 才允许写 Phase 2；
- 189 个 Task 没有复杂度权重，但采用同一验收和提交模板；
- 单会话、单任务、单阶段串行，前端、Provider 和后端即使文件无交集也不能并行；
- “代码已实现但尚未资格测试”没有独立状态，只能在 `NOT_STARTED` 与 `ACCEPTED` 之间反复回开。

## 3. 双状态模型

开发完成度和运行能力必须分开记录。

### 3.1 开发完成度

```text
NOT_STARTED
  → BUILDING_CLOSED
  → BUILT_CLOSED
  → INTEGRATING_CLOSED
  → SYSTEM_CODE_COMPLETE_CLOSED
  → QUALIFYING
```

| 状态 | 含义 | 可以做什么 | 不能声称什么 |
|---|---|---|---|
| `NOT_STARTED` | 尚无受控实现 | 规划、契约预检 | 代码存在 |
| `BUILDING_CLOSED` | 正在快速构建 | 合并关闭态代码 | 功能已验收或可用 |
| `BUILT_CLOSED` | 本批代码通过快速门 | 被后继批次通过稳定 `Produces` 接口消费 | 集成、HA、安全、恢复已通过 |
| `INTEGRATING_CLOSED` | 多批次正在系统集成 | 运行实验室集成测试 | 真实 Provider 或生产就绪 |
| `SYSTEM_CODE_COMPLETE_CLOSED` | 规划内生产代码、API、前端和装配均已实现并保持关闭 | 进入集中资格测试 | 任何能力 `AVAILABLE` |
| `QUALIFYING` | 正在执行真实资格测试 | 逐项收集实验室/真实依赖证据 | 跳过独立 Provider/Action 门 |

### 3.2 运行能力

原有运行状态保持不变。`BUILT_CLOSED` 或 `SYSTEM_CODE_COMPLETE_CLOSED` 不会把 Source、Connection、Capability、READ Admission、Action 或 Release 改为可用。只有相应真实资格门通过后，才可从 `UNAVAILABLE/CLOSED` 进入原计划定义的 accepted/available 状态。

`docs/status/current.md` 是两种状态的唯一当前事实源。任务包 checkbox 是范围和最终验收清单，不再作为快速构建完成度的唯一表达。

## 4. 工作类型与不可延后门

### 4.1 C0：安全与公共契约

包括：

- 数据库迁移、复合 Scope、不可变状态和 down guard；
- 公共 OpenAPI、生成 DTO 和跨阶段 `Produces` 接口；
- OIDC 身份、授权、recent-auth、职责分离；
- digest、canonicalization、fence、lease、idempotency 和 transaction closure；
- Credential、Secret、Runner payload、READ/WRITE 隔离；
- ActionPlan、Approval、WRITE admission、verification 和 audit chain。

C0 改动不能“只编译不测试”。快速构建期至少需要一个会因错误实现真实失败的定向行为测试或现有回归测试，以及必要的 Go↔SQL/OpenAPI parity。C0 不要求每次运行无关的全仓 race、双实例恢复或所有 Provider E2E。

### 4.2 C1：核心纵向产品切片

包括同一用户流所需的领域、Repository、API、生成类型、页面和关闭态生产装配。允许实现优先，但必须在批次合并前补齐关键 happy path、拒绝路径和错误投影测试。

### 4.3 C2：Provider 与页面广度

包括 CMDB、vSphere、Proxmox、OpenStack、AWS、Azure、GCP、Kubernetes Operator、AWX，以及各类详情页和治理库存页。公共 Source/Connection/Runtime 接口冻结后可并行实现。快速构建期可使用测试 fixture、协议录制和本地 fake server，但生产包必须包含真实窄 Adapter，且 registry/gate 默认关闭。真实账户、真实网络、HA takeover、rate-limit 和 canary 延后到资格测试。

### 4.4 Q：资格与发布证据

包括全量 race、多实例、恢复、HA、容量、真实 Provider、Keycloak、Vault、mTLS、Playwright/axe、安全攻击矩阵、混沌、DR、Canary 和生产发布签名。Q 工作在代码完成后集中执行，不和每个实现 Task 重复交织。

## 5. 四级验证体系

### 5.1 G1 Fast Change Gate：每个实现 PR

所有 PR 必须通过当前 GitHub 快速 `go` required check：

```bash
go mod verify
test -z "$(gofmt -l .)"
git diff --check
go vet ./...
go build ./cmd/control-plane ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/executor
```

本地额外只运行受影响范围：

- `go test` 受影响包，不默认加 `-race`、`-shuffle` 或全仓 `./...`；
- 修改迁移时，在一个 disposable PostgreSQL 18.4 数据库执行定向 up smoke、受影响 schema admission 和契约测试；
- 修改 OpenAPI 时执行 lint/generate，并确认唯一生成类型无 drift；
- 修改 `web/` 时执行受影响测试、typecheck、lint 和 build；
- 修改 C0 时运行对应安全负向或 parity 测试。

G1 失败必须修复。未运行的 G2–G4 项记录为 deferred qualification，不得写成 PASS。

### 5.2 G2 Batch Integration Gate：每 2–4 个相关旧 Task 或一个稳定切片

一个 Batch 目标为 1–2 个工作日、一个独立 worktree、一个 PR。G2 包含：

- 受影响包的完整 unit/integration 测试；
- 只对并发敏感包运行定向 `-race`；
- 涉及迁移时运行该迁移的 up/down/up 和受影响 admission，不跑无关双实例恢复；
- 涉及 API/Web 时运行该切片的契约生成、组件和一条本地 E2E；
- 一次独立代码复核，重点是 P0/P1、越权、Secret、数据破坏和接口漂移；
- `git diff --check`、生成物漂移、定向 secret scan 和提交边界审计。

一个局部纠错只有在代码地图/影响分析证明涉及恢复格式、归档 owner/ACL、持久数据解释或跨版本兼容时，才升级到恢复/双实例门。

### 5.3 G3 Milestone Gate：纵向闭环或 3–5 个 Batch

G3 运行：

- 相关领域的跨包测试和 `-race`；
- 本阶段已修改迁移的组合 up/down/re-up；
- PostgreSQL + Keycloak + mTLS/Runner 的实验室集成；
- OpenAPI → generated types → Go HTTP → Web 的闭环测试；
- 一条真实浏览器 happy path 和关键 fail-closed 路径；
- 一次架构/安全复核；
- 手动运行重型 GitHub workflow。

G3 只允许将批次标为 `INTEGRATING_CLOSED` 或 `SYSTEM_CODE_COMPLETE_CLOSED`，仍不打开生产能力。

### 5.4 G4 Real Qualification Gate：系统代码完成后

G4 分四轮：

1. **Q1 确定性实验室资格**：全仓 unit/race/vet/build、全部迁移、恢复、并发、契约、生成物、Secret/DLP。
2. **Q2 真实依赖资格**：真实 PostgreSQL/Keycloak/Vault/Temporal/mTLS 和各 Provider 非生产实例，验证协议、身份、限流、checkpoint、cleanup 和恢复。
3. **Q3 系统资格**：多副本 HA、故障注入、备份恢复、容量、Playwright/axe/视觉、安全攻击矩阵、SLO 与 Runbook 演练。
4. **Q4 发布资格**：SHADOW、READ_ONLY、逐 Action 非生产 drill、supervised canary、波次发布和最终签名。

G4 证据仍按原任务包和覆盖矩阵逐项回填。缺证据的 Provider、Capability 或 Action 继续 `UNAVAILABLE/CLOSED`，不阻塞已经独立通过的其他类型。

## 6. 测试策略

- Bug 修复、C0 契约和未知行为继续优先 RED → GREEN。
- C1/C2 快速构建允许实现与测试同批完成，不强制先提交 test-only RED。
- 已经存在的实现可以补 characterization/contract tests；不得为了满足历史顺序伪造 RED。
- 测试必须验证行为，不以纯文本搜索替代数据库/API/运行时行为；静态架构测试只用于所有权、调用点和禁止入口。
- 大型穷举矩阵只在它能防止高风险边界漂移时保留。字段 clone、DTO shape 和 enum 可用代表性表驱动/生成测试，避免数千行手写镜像实现。
- 后补测试至少通过 fault injection、受控 mutation、错误 fixture 或覆盖已有真实缺陷证明能失败；不能只证明当前实现是绿色。
- flaky、环境缺失或 Skip 不能算 PASS。快速构建期可以 deferred，但必须保持能力关闭并进入 G4 清单。
- 测试 fake/MSW/loopback 只能在测试路径；生产装配不能依赖 fake，也不能用占位标记、panic 或空成功返回冒充代码完成。

## 7. 快速开发路线

### Milestone 0：恢复正确基线

- 定向修复 `EXPLICIT_ITEM_ENVIRONMENT` 与 `000015` 的 P0 parity；旧 `MULTI_ENVIRONMENT` 保持拒绝。
- 完成 Phase 1 Task 2 领域/Auth/Fence 的最小正确实现；删除测试中的假约束和重复穷举，不再等待多轮 test-only reviewer。
- 通过 G2 后把 Pack 01 标为 `BUILT_CLOSED`；不重跑与枚举/领域无关的双实例恢复和全仓安全矩阵。

### Milestone 1：资产核心闭环

- Phase 1 Packs 02–05：Repository/Observation、Mapping/Auth/API、Web Foundation、Manual/CSV/API Source。
- Phase 1 Pack 10：Overview 使用显式 `NOT_STARTED/UNAVAILABLE` 投影显示未实现领域。
- 产出可运行但关闭的 Manual/CSV/API 资产 → API → Web 纵向路径。

### Milestone 2：Connection 与 Runtime 核心

- Phase 2 Packs 01–06：schema/domain、Repository/compiler、Validation identity/protocol、OpenAPI/HTTP、Web publication flow。
- Phase 2 Pack 07 的安全只读库存可与 Web 后半段并行；Pack 08 的真实 E2E 留到 G4。
- 产出关闭态 Connection revision → validate → publish → immutable Runtime 路径。

### Milestone 3：首条只读调查闭环

- Phase 3 Packs 01、03、04、05：taxonomy、Metrics/Logs/Traces typed contracts/runtime/API/Web。
- Phase 4 Packs 01–06：Snapshot、Grant、Policy、Gateway、Evidence、ActionProposal、Web。
- Phase 5 优先 Packs 01–03、05–07 的 PostgreSQL 路径；Host Probe/AWX 广度并行后补。
- 产出关闭态 Asset → Connection → Runtime → Grant → typed READ → Evidence → `PROPOSAL_ONLY` 路径。

### Milestone 4：平台与受治理 Action 代码闭环

- Phase 6 先完成生产装配、身份/网络、SLO/状态代码；真实 HA/DR/rollout 演练留到 G4。
- Phase 7 Packs 01–06 实现 Action catalog、Plan、Policy/reauth/approval、WRITE credential/Runner、verification/reconciliation/rollback、API/Web；Action gate 全部保持 `CLOSED`。
- Phase 8 先实现 release schema/gate、Helm/状态投影和 staged rollout 控制代码；容量、混沌、合规和真实波次在 G4。
- 达到 `SYSTEM_CODE_COMPLETE_CLOSED` 后停止继续铺功能，进入资格测试。

### Milestone 5：Provider 广度收敛

公共 Source/Connection/Runtime 接口冻结后，以下工作可与 Milestones 2–4 并行，但各自独立 worktree/目录所有权：

- Phase 1 Packs 06–09：CMDB、vSphere、Proxmox、OpenStack、AWS/Azure/GCP、Discovery Worker；
- Phase 3 Pack 02：VictoriaMetrics Operator 21 类资源发现；
- Phase 5 Host Probe/AWX enrollment/read adapter；
- 各 Provider 对应页面、安全投影和关闭态 registry；
- 各阶段 metrics/runbook/test harness 骨架。

真实账户、真实集群、HA takeover 和可用性签名统一在 G4 执行。

## 8. 并发与文件所有权

主管理任务可同时维护最多三个实现会话，另保留一个主管理/集成槽位。只有稳定接口已合并到 `origin/main` 后才并行。

| 轨道 | 主要所有权 | 禁止并行修改 |
|---|---|---|
| Contract/Core | 当前迁移、Go domain/repository、OpenAPI、HTTP | 其他轨道不得改同一 migration/OpenAPI/domain interface |
| Provider/Runner | 独立 Provider package、adapter、fixture、runner profile | 不得自行扩展公共 DTO、迁移或 Capability enum |
| Web/Product | `web/src/features/*`、既有 generated types 的 consumer | 不得手改 `schema.d.ts` 或另造 DTO/transport |
| Manager/Integration | `docs/status/current.md`、跨轨道合并、批次 gate、任务交接 | 不直接改其他会话 worktree |

共享文件规则：

- 同一时刻每个 migration 只有一个 owner；迁移按 `000015`→`000022` 顺序合并。
- `api/openapi/control-plane-v1.yaml` 与 `web/src/shared/api/schema.d.ts` 由同一个 Contract owner 维护。
- `docs/status/current.md` 只由主管理/集成批次更新。
- 后继轨道只消费已合并的 `Produces` 接口，不读取其他会话未提交内部实现。
- 发现契约缺口时只暂停受影响轨道；无依赖轨道可继续，能力仍关闭。

## 9. PR、窗口与交接

- 一个 Batch 使用一个隔离 worktree、一个命名分支、一个 PR；目标为 2–4 个相关旧 Task，而不是每个旧 Task 一个 PR。
- PR 必须列出：范围、C0/C1/C2 分类、base SHA、G1/G2 结果、deferred G3/G4、关闭状态、风险和后继 `Produces`。
- GitHub 日常只要求快速 `go`；重型 workflow 在 G3/G4 手动运行。
- Batch 通过 G2 后 squash merge `main`，验证远端 main，再归档旧会话；新窗口从最新 `origin/main` 继续下一 Batch。
- 上下文在任务包/Batch 边界轮换，不因每个 checkbox 轮换，也不让一个窗口跨越多个无关领域。
- 不允许把未提交脏区直接交给下一会话；要么形成明确提交，要么由原会话保留并继续。

## 10. 进度与质量指标

第一个 5 日快速构建周期只校准速度，不承诺虚假日期。主管理任务每日记录：

- 合并 Batch 数和加权规模（S/M/L，L 必须拆分）；
- `BUILT_CLOSED` 纵向切片数；
- G1/G2 首次通过率；
- 返工小时和契约冲突数；
- deferred G3/G4 数量；
- 泄漏到后继 Batch 的 P0/P1 数量；
- 活跃脏文件数和最长未合并时间。

目标：

- Batch 在 2 个工作日内完成；超过即拆分或升级阻塞；
- G1 首次通过率 ≥90%；
- 后继 Batch 发现的上游 P0 为 0，P1 在一个 Batch 内回收；
- 同一测试矩阵最多一次独立 test-quality review，除非发现真实 P0/P1；
- 真实资格阶段开始前，所有 deferred 项都有归属 Batch/Provider/Capability/Action，且对应运行能力仍关闭。

### 10.1 暂定周期

以下是容量目标，不是发布承诺；第一个 5 日周期后必须用实际吞吐重算：

| 范围 | 暂定周期 | 主要条件 |
|---|---:|---|
| M0 正确基线 | 2–4 个工作日 | 当前 RED 清理、枚举修正和 Task 2 同批完成 |
| M1 资产核心 | 2–3 周 | OpenAPI/Web 基础与 Manual/CSV/API 纵向闭环 |
| M2 Connection/Runtime | 2–3 周 | 可与已冻结接口后的 Provider/Web 轨道重叠 |
| M3 首条 READ 调查闭环 | 3–5 周 | 优先 PostgreSQL 路径，不等待所有 Provider 广度 |
| M4 平台/Action/Release 关闭态代码 | 4–6 周 | WRITE 与 release gate 始终关闭 |
| M5 Provider 广度 | 4–8 周，重叠执行 | 取决于 SDK、fixture 与非生产依赖可获得性 |
| 达到 `SYSTEM_CODE_COMPLETE_CLOSED` | 约 10–16 周 | 三条实现轨道持续工作、无连续公共契约返工 |
| G4 真实资格 | 约 6–10 周 | 真实账户/集群、HA/DR/安全/容量环境按时可用 |

因此当前合理目标是约 4–6 个月形成可签名的完整生产闭环，而不是把 189 个 Task 按原方法串行执行。若 5 日校准显示加权吞吐低于目标，优先继续拆 L Batch、减少共享文件冲突和补齐测试夹具，不通过删除安全契约来追日期。

## 11. 真实测试阶段入口

只有以下条件同时成立，才进入 `SYSTEM_CODE_COMPLETE_CLOSED → QUALIFYING`：

- `000015`–`000022` 的生产迁移和 down guard 均已实现；
- 规划内 Go domain/repository/API/worker/runner/executor 生产实现存在，不依赖测试 fake；
- 单一 OpenAPI、生成 TypeScript、`web/` 页面和同源 Go SPA 装配完成；
- 每个 Provider/Capability/Action 都有真实窄实现或明确保持未实现，不存在通用 endpoint/payload/shell/SQL 旁路；
- 所有代码通过 G1，所有核心 Milestone 通过 G3；
- READ admission、WRITE admission、Provider gates 和 Release gate 默认关闭；
- `docs/status/current.md` 列出 deferred qualification，不把 code-complete 写成 available。

进入真实测试阶段后冻结新功能范围，只处理资格失败、缺失证据和生产阻塞。只有独立签名的原计划 phase/release decision 才能改变 accepted/available 状态。

## 12. 当前立即执行的 Batch

`M0-asset-domain-contract`（PR #34）、`M1A-asset-governance-repository`（PR #38）、`M1B-asset-source-read-projection`（PR #41）、`M1C-discovery-data-plane-contract`（PR #42）、`M1D-checkpoint-codec-foundation`（PR #44）与 `M1E0-repeated-empty-relation-page-corrective`（PR #46）均已合并并保持 `BUILT_CLOSED / UNAVAILABLE`。M1E0 已把 `000015` 两处“必须不同于上一页”谓词收窄为 exact canonical-empty digest 例外，相同非空 digest、sequence、checkpoint、fence 与 exact receipt 闭包仍由 PostgreSQL 18.4 真库证明。

`M1C1-normalized-fact-contract-corrective` 已由 PR #49 合并：DisplayName 256-byte parity、跨 Environment structural Policy Reference、六元 relation identity 与 present-frame page-byte accounting 已通过三个真实 RED、两包 unit/race、G1/G2 和独立复核。Opaque reference 仍不等于策略许可。

当前从最新 `origin/main` 创建 fresh [M1E — Atomic Page Commit Transaction](2026-07-13-governed-operations/01-assets/13-m1e-page-commit-transaction.md) 窗口。M1E 精确拥有两个 `discoverysource/page_commit*` contract 文件与三个 PostgreSQL PageCommitter/projection/integration 文件；公开 ABI、receipt-first/single-Seal 顺序、canonical page/relation identity、locked Revision Fact/relationship-policy resolver、one-transaction closure、错误 vocabulary 与 G2 证据只在该任务包定值，Pack 02/09 仅引用而不另造平行版本。

Queue 公共 ABI 与进程内 ClaimResult 的 sealed `LeaseFence` 仍只在真实 PostgreSQL lifecycle 消费点一起定值；持久化/可序列化 Queue payload 永不携带 fence。M1E 完成后 Queue lifecycle/cleanup/limiter 再按文件所有权分片收口；所有后继关闭态 Batch 最多记为 `BUILT_CLOSED`，资产运行能力继续 `UNAVAILABLE`。
