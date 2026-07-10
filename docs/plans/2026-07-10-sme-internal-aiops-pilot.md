# SME Internal AIOps Pilot Implementation Plan

> 执行方式：在 `feat/sme-internal-aiops` worktree 中按任务顺序实施；每项逻辑遵循测试先行，完成后进行规格审查和代码质量审查。

**Goal:** 交付一个可本地运行、可测试、可对接真实企业端点的调查与受控执行平台核心，并保留生产灰度所需的不可绕过安全边界。

**Architecture:** Go 模块化单体负责领域与 API，PostgreSQL 保存事实，Temporal 编排长流程，环境 Runner 以出站租约方式查询或执行类型化动作。模型仅产生结构化假设/提案，CEL、审批、短期凭据和 Runner 共同构成执行信任链。

**Tech Stack:** Go 1.26.5、chi、pgx、Temporal Go SDK、cel-go、OpenTelemetry、PostgreSQL、React/TypeScript/Vite、S3-compatible storage、Keycloak、Vault。

---

## Task 1：文档与仓库基线

**产出：** V3权威蓝图、实施计划、README、AGENTS、Makefile、版本策略、CI骨架。

**步骤：**

1. 保留旧蓝图，新建 V3 蓝图和本计划。
2. 固定 Go 1.26.5，记录 `toolchain` 和 CI 版本。
3. 创建模块化目录：`cmd/control-plane`、`cmd/worker`、`cmd/runner`、`internal`、`migrations`、`web`、`deploy`、`docs`。
4. 添加配置加载、结构化日志、错误约定和健康端点的失败测试。
5. 实现最小程序并运行 `go test ./...`、`go vet ./...`。

**验收：** 三个二进制可编译；健康端点测试通过；仓库无明文密钥。

## Task 2：领域契约和持久化

**产出：** Tenant、Workspace、Environment、ServiceBinding、Signal、Incident、Investigation、Evidence、Hypothesis、Feedback、ActionPlan、PolicyDecision、Approval、Execution、AuditRecord、Outbox。

**步骤：**

1. 先为状态转换、服务映射、人工确认根因和不可变计划编写单元测试。
2. 实现纯领域类型与验证；`AMBIGUOUS/UNRESOLVED` 禁止动作计划。
3. 创建 PostgreSQL migrations、Repository 接口和内存实现。
4. 添加 pgx 实现与 Testcontainers 集成测试。
5. 实现 Outbox claim/ack/retry 和重复分发测试。

**验收：** 非法转换、跨Workspace引用、重复Signal和旧版本更新均被拒绝；数据库与内存实现通过同一契约测试。

## Task 3：HTTP API 与信号接入

**产出：** `/healthz`、`/readyz`、`/api/v1`、RFC9457错误、幂等键、游标、ETag、Alertmanager/夜莺Webhook。

**步骤：**

1. 以 `httptest` 编写路由、错误、幂等冲突和游标测试。
2. 实现 Request ID、OIDC principal、Workspace scope 和审计中间件。
3. 实现 SignalEnvelope 规范化、provider event ID 唯一约束、payload hash冲突检测和指纹去重；Webhook不要求平台`Idempotency-Key`。
4. 实现 Incident 创建/归并和异步 Investigation 触发。
5. 添加重复、乱序和告警风暴测试。

**验收：** Webhook快速ACK；同一事件不重复创建；同幂等键不同载荷返回409。

## Task 4：只读连接器与服务上下文

**产出：** Prometheus、VictoriaLogs、Kubernetes、AWX、GitLab、Jenkins、GitHub Actions、Argo CD适配器。

**步骤：**

1. 定义窄 `QueryProvider`、`HealthChecker` 契约和公共预算。
2. 为每个HTTP适配器编写本地契约服务器测试。
3. 实现PromQL即时/区间查询；实现LogsQL query/hits/stats并强制时间、字段、limit、timeout。
4. 实现K8s只读资源/Event接口；实现AWX inventory/job只读接口。
5. 实现三套CI/CD和Argo revision/health/history时间线。
6. 所有结果转换为带来源、时间和哈希的Evidence。

**验收：** 超时、截断、限流和部分失败均可见；任何连接器都不能绕过预算。

## Task 5：Investigation、模型与评测

**产出：** 确定性调查模板、混合模型路由、结构化Hypothesis、反馈与离线评测器。

**步骤：**

1. 为四类黄金事故编写fixture和期望Evidence/Hypothesis测试。
2. 实现有界并行收集和 `PARTIAL` 降级。
3. 实现数据分类、脱敏、私有/云端路由和模型预算。
4. JSON Schema 校验模型输出，只接受证据引用、未知项和类型化提案。
5. 实现人工确认/驳回/纠正及评测指标。
6. 添加提示注入、模型超时、格式错误和fallback测试。

**验收：** 模型失败仍输出证据报告；无证据文本不得成为观察；只有人工可确认根因。

## Task 6：Temporal 与 Runner 协议

**产出：** Investigation/Approval/Execution Workflow，出站Runner lease/heartbeat/complete协议。

**步骤：**

1. 为Workflow replay、等待审批、超时、取消和Activity重试编写测试。
2. 实现Outbox到Temporal dispatcher，Workflow只传ID。
3. 实现Runner队列、lease epoch、心跳、完成和fencing。
4. 只读和变更Runner使用不同配置、身份和队列。
5. 添加重复领取、旧租约回写、Runner崩溃和网络分区测试。

**验收：** 重放不产生重复副作用；旧Runner不能覆盖新租约结果。

## Task 7：ActionEnvelope、CEL、审批与执行

**产出：** 规范化计划哈希、三次策略重评、风险分级审批、Kill Switch、四类执行器骨架。

**步骤：**

1. 先写规范化哈希、篡改、过期、申请人自批、策略变化和状态漂移测试。
2. 实现ActionEnvelope、SHA-256 plan_hash和版本化CEL策略。
3. 使用JCS规范化载荷和Vault Ed25519密钥完成签名；Runner实现公钥集、`key_id`、轮换窗口、吊销和验签失败测试。
4. 实现单/双人审批及30分钟有效期。
5. 实现Vault凭据接口，凭据不持久化；测试用短期内存凭据实现。
6. 实现K8s Deployment重启、无HPA扩缩容、GitOps revert MR/PR、AWX Linux/Windows服务重启类型化执行器。
7. GitOps Workflow显式等待外部分支保护审批、检查、人工合并和Argo auto-sync；计划绑定base/head commit及diff/tree hash，MR head变化使审批失效，合并后验证结果tree再等待Argo；添加追加提交、force-push、merge结果漂移测试。平台不得绕过规则或直接参数覆盖。
8. 实现目标锁、全局并发1、四级Kill Switch、验证和对账。

**验收：** 任意命令和未知动作拒绝；计划变化后审批失效；不确定结果不盲重试；AWX不提供虚机重启。

## Task 8：Web 与飞书

**产出：** 事件、调查、证据、假设反馈、计划、审批、执行、审计、服务映射页面；飞书卡片。

**步骤：**

1. 创建TypeScript API client和关键页面组件测试。
2. 实现OIDC登录和角色/资源范围显示。
3. 实现事件详情的证据/假设/未知项/数据缺失视图。
4. 实现反馈和人工确认根因。
5. 实现计划diff、审批约束、执行验证和审计视图。
6. 飞书只展示进度与Web审批深链，不在卡片直接批准生产动作。

**验收：** 关键流程具备组件测试和浏览器E2E；无控制台错误；敏感正文默认隐藏。

## Task 9：部署、观测与供应链

**产出：** 本地compose、生产Helm、Keycloak/Vault/Temporal/对象存储集成说明、OTel、SBOM和镜像签名流程。

**步骤：**

1. 提供最小本地profile和外部依赖健康检查。
2. 提供控制面/Worker三副本、read/write Runner分离、NetworkPolicy、PDB和资源限制。
3. 添加指标、trace和脱敏日志；内容采集默认关闭。
4. 添加数据库备份/恢复和RPO/RTO演练脚本。
5. 实现每日审计哈希清单、前序摘要链、Vault Ed25519签名、S3 Object Lock/WORM写入、离线验签和恢复演练；开发环境明确降级保证。
6. CI执行测试、vet、静态分析、SBOM、镜像扫描和签名。

**验收：** 本地一条命令启动；Helm模板验证通过；秘密不进入镜像、日志和Temporal History。

## Task 10：安全、负载和端到端验收

**步骤：**

1. 运行跨Workspace、提示注入、计划篡改、伪造签名、旧租约、凭据吊销和任意命令安全测试。
2. 运行连接器、Worker、Runner和数据库故障注入。
3. 压测1000告警/分钟持续10分钟和20并发调查。
4. 验证TTFUE p95<60秒、报告p95<180秒。
5. 为每类动作完成≥20次非生产执行，再进行5服务生产灰度。
6. 生成Go/No-Go报告；任一安全指标失败时保持write feature flag关闭。

**最终验收：** 与V3蓝图第11章门槛逐项对照，附命令、日志摘要、指标和未完成的外部联调证据。
