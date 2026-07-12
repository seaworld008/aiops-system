# Immutable Investigation Plan Manifest v1

本文说明 M5C1B0 的调查规划 manifest。它把已持久化 Signal 的匹配事实转换为精确的
Incident 关联作用域和 READ `TaskSpec`，但不执行关联、创建 Investigation、启动 Temporal
Workflow 或开放 Runner claim。Planner 是启动期构造的纯内存不可变对象，没有热更新、
数据库回退或进程级可变 registry。

本里程碑不修改任何 `cmd/*`、配置装配或数据库迁移。Signal dispatcher 仍未安装到
Worker，Control Plane 的 READ claim/start/completion 门禁仍保持 disabled。生产写继续
不存在可配置启用路径。

## Manifest v1 契约

顶层 `schema_version` 固定为 `investigation-plan-manifest.v1`，并包含与同一进程内
immutable READ connector registry 精确绑定的 `registry_digest` 和 1–1000 个
`profiles`。每个 profile 由以下三部分组成：

- `scope`：精确的 `tenant_id`、`workspace_id`、`environment_id`、`service_id`；四者均为
  小写 RFC 4122 UUID v1–v5。
- `match`：精确的持久 `integration_id`、规范小写 `provider`，以及 1–16 个
  `{"key":"...","value":"..."}` label 条件。
- `tasks`：1–12 个由 `key`、`connector_id`、`operation`、对象型 `input` 组成的 READ
  任务定义。

Manifest 不支持 priority、default、regex、wildcard、negative match 或运行时
`mapping_status`。Task 不得携带 scope、`TargetRef`、query、endpoint、credential、header、
argv、env 或任意命令材料。连接目标、固定查询、输出投影和预算继续只由已校验的 READ
connector registry 决定；规划 manifest 只能引用 registry 中已经存在且与完整
Tenant/Workspace/Environment/Service scope 精确一致的 ConnectorID/Operation。

所有 profile 在 Planner 构造时先规范化 TaskSpec，再调用 registry authorizer 做完整准入。
这次启动期准入不替代持久化边界：后续 Repository 创建 Investigation/Task 时仍必须在锁定的
可信 Incident scope 下用同一 digest 对应的 registry 重新授权，不能直接信任 Plan 快照。
构造函数在任何深拷贝或 JCS 计算之前，对字符串、labels 和 task input 等全部定义材料执行
溢出安全的 1 MiB 聚合预算检查；因此调用内存 API 不能绕过文件大小上限。构造成功后，
Planner 和解析出的 Plan 都只返回深拷贝；安全字段为私有、不可从 JSON 反序列化，格式化或
序列化时保持脱敏。

## 可信作用域与精确匹配

Tenant/Workspace 授权不能来自 Signal、HTTP/Outbox payload 或 manifest 内可覆盖字段。
调用方必须先通过服务端可信注册创建不可序列化的 `TrustedSignalScope`；注册只包含持久
`tenant_id` 与 `workspace_id`，并在创建时校验。解析请求还必须提供当前 Planner 的精确
`ExpectedPlanDigest`，缺失或不一致都失败，不能回退到“最新”或默认 plan。

`domain.Signal` 只提供匹配和相关性事实：

- `Signal.WorkspaceID` 必须与可信注册的 Workspace 完全相同；
- `IntegrationID`、`Provider` 和 labels 只参与 profile 选择；
- `Fingerprint` 只参与确定性 correlation key；
- Signal 不能覆盖 Tenant、Environment、Service、mapping status 或 Task scope。

Profile 匹配维度固定为 Tenant、Workspace、Integration、Provider 和 label 精确合取。Signal
可以包含额外 labels，这些额外字段被忽略；声明的每个 label 则必须精确存在且值相同。
不存在 regex、前缀、缺省或优先级决胜规则。

Planner 在启动时证明同一 Tenant/Workspace/Integration/Provider 下的 profiles 互斥：如果
两个 profile 的公共 label 中没有至少一个键具有不同值，它们就可能同时命中，必须拒绝整份
manifest；即使两者产生完全相同的 Task，也不允许用“输出相同”掩盖配置歧义。不同
Tenant、Workspace、Integration 或 Provider 天然互斥。运行时匹配数为 0 时返回 unresolved；
匹配数不等于 1 的其他情况视为 Planner 完整性故障并 fail closed。

## 四个摘要与相关性键

M5C1B0 保留四个互相独立、均为完整小写 SHA-256 十六进制的摘要：

| 摘要 | 绑定内容 | 用途 |
| --- | --- | --- |
| Registry digest | READ connector registry 的精确 scope、ConnectorID、固定执行契约与预算；不含 Secret | 证明 Task 所引用的连接器语义版本 |
| Tasks hash | 现有 `investigation.task-specs.v1` 规范化 TaskSpec 集合 | 复用 Repository 的 Task 幂等语义 |
| Profile digest | 域分隔 JCS：registry digest、scope、规范化 match、tasks hash 与规范化 TaskSpec | 证明一次 profile 选择的全部规划语义 |
| Manifest/plan digest | 域分隔 JCS：registry digest 与排序后的全部 profile digest | 标识一份不可变 plan manifest |

Labels 和 TaskSpec 先按各自规范排序；manifest digest 对 profile 声明顺序不敏感，但对任何
安全语义变化敏感。所有摘要都由服务端自行计算，不能信任配置或 Runner 提供的派生 hash。
Planner 构造时要求 manifest 声明的完整 registry digest 与注入 registry 的当前 digest
精确一致，并要求 registry 非空且 Ready；不提供部分 registry 或 digest mismatch fallback。

Plan 还生成 `corr.v1.<sha256>` correlation key。它使用独立域分隔 JCS，只绑定
Tenant/Workspace/Environment/Service、Integration、Provider 和 Fingerprint，不绑定
Signal status、ObservedAt、ProviderEventID、原始 labels、TaskSpec 或 plan digest。因此同一
已解析服务目标的 firing/resolved 事件具有稳定相关性，而 profile/registry 版本仍由上述四个
摘要独立追踪。

## 安全文件加载

Manifest 与 READ connector registry 共用 `internal/securemanifest` 的 fail-closed 文件
加载和严格 JSON 解码，但各自继续保留自己的低敏错误分类。加载要求：

- 路径必须是已清理的绝对路径，长度不超过 4096 字节；最终组件以
  `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` 打开，不跟随 symlink；
- 对象必须是当前 euid 拥有、hardlink 数为 1、非 group/world writable 的 regular file，
  总大小不超过 1 MiB；
- 在同一 FD 上双读并复核 identity、size、mode 和 modification time，读取期间发生变化即
  拒绝；
- Darwin/Linux 的扩展 ACL 与未知 xattr 均 fail closed；不受支持的平台直接拒绝，不能
  降级为普通 `os.ReadFile`；
- JSON 必须是 UTF-8、最大嵌套深度 16；对象字段只能使用规范 `snake_case`，未知字段、
  重复字段（包括转义后重复）和尾随文档均拒绝；
- callback 成功、返回错误或 panic 的所有退出路径都清零临时内容；错误、日志和格式化输出
  不得回显路径、manifest 内容、Task input 或其他 canary。

文件加载失败、registry 未 Ready、digest 不一致、profile 重叠、Task 未通过 registry
authorizer 或请求作用域不一致时都直接失败；没有内存默认配置、旧文件回退或跳过坏 profile
的路径。

## B1 History 与 digest-bound queue 后续契约

M5C1B0 只产生不可变 Plan，不引入 Temporal SDK。后续 B1 Workflow History DTO 必须只携带
持久 ID、脱敏状态以及上述四个摘要，不携带 manifest 正文、Task input、目标、凭据或连接器
错误体。Activity task queue 必须与 plan/registry digest 绑定，使 Worker 只能处理它明确支持
的不可变契约。

滚动升级时，仍有旧 digest History/Task 的兼容 Worker 必须保留到对应 Workflow 和 READ
Task 终态；新 Planner 不得用同名新定义重新解释旧 digest。移除最后一个兼容 Worker 前应先
证明旧 digest backlog 为零。这个兼容策略属于后续 B1 assembly/rollout，当前里程碑没有创建
task queue、注册 Workflow/Activity 或启动 Worker。

## 当前 rollout 边界

- 无数据库迁移；Plan 和 Trusted scope 都不持久化。
- 无 Temporal SDK、Workflow、Activity、task queue 或 History DTO 实现。
- 无 `cmd/*`、环境变量、Control Plane 或 Worker assembly 变更；Signal dispatcher 仍未
  安装，Outbox 继续停在未 ACK 的安全等待点。
- READ Runner target manifest、digest 一致性门禁和固定执行器尚未完成，READ claims、遗留
  lease start/completion 继续关闭。
- 本功能只生成 READ 调查规划，未连接 ActionPlan、策略、审批、WRITE Runner 或 Executor；
  `AIOPS_WRITE_EXECUTION_MODE` 和生产写路线图门禁均不变，生产写仍不可配置启用。
