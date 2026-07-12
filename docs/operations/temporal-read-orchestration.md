# Temporal READ investigation orchestration

阶段：M5C2-4b / M5C2-4c1a / M5C2-4c1b / M5C2-4c2a（版本化只读编排、Plan-bound Runner
路由、角色隔离的 Temporal 控制边界与 fail-closed 子进程 containment；真实 Worker/Outbox/Runner
尚未装配，READ claims 关闭）

本阶段把既有 investigation preparation、持久 READ Task、mTLS Gateway、结果恢复和 atomic
runtime Bundle 连接成可 replay 的 Temporal v2 协议，并由不可互换的 Starter/Control Client、严格
converter、sealed Starter/Control Worker 和 Snapshot 高层工厂封闭控制侧装配边界。C2-4c2a 只把
`cmd/worker` 变成固定 self-reexec 父监督器；它不装配 Temporal、PostgreSQL 或 Outbox，隐藏 child 会在
READY 前固定失败。该切片不修改配置、Outbox dispatcher、Gateway Admission、迁移或业务 HTTP API。Control Plane 仍安装关闭态
Admission，生产代码仍没有打开 READ claims 的构造器；WRITE claims 与 production write 也继续不存在
启用路径。

## C2-4c2a 进程级 containment

C2-4c2a 只建立“父进程能否确定性终止并回收失控 Worker 子进程”的底座，不宣称 live Worker 或
fatal/normal-stop overlap 门禁已经完成：

- 外部 `cmd/worker` 仍只接受零参数。父进程在 Linux 固定执行 `/proc/self/exe` 和唯一隐藏 child 参数，
  不接受 executable、argv、shell、环境变量或超时覆盖；child 必须持有父进程通过匿名 pipe 继承的状态
  FD，直接伪造隐藏参数会 fail closed。
- child 使用独立进程组和 `Pdeathsig=SIGKILL`，无 stdin、空环境和固定工作目录；stdout/stderr 仅进入
  有界丢弃 sink，任何内容或退出文本都不能进入父进程错误、日志或审计。child 接受状态 FD 后立即设置
  `CLOEXEC`，后续意外 exec 不能继承状态写能力。
- 状态协议在启动期只允许单字节 `READY` 或 `FATAL`，READY 后只允许最多一次 `FATAL`。Supervisor 与
  状态 FD capability 都带 self/seal 校验，值复制不能产生第二次 Run 或重复状态写权限。未知、重复、
  额外字节、READY 前 EOF、通知丢失或输出洪泛全部按协议破坏处理。
- 启动最长 30 秒；启动失败按 `SIGTERM → 2 秒 → SIGKILL → Wait` 收敛。正常关闭按
  `SIGTERM → 45 秒 → SIGKILL → Wait` 收敛，45 秒覆盖 SDK 固定 35 秒 stop budget；加上两段 5 秒
  containment/reap 确认及最多 100 毫秒退出分类后，最坏启动、正常关闭和异常路径预算分别为 42、55
  和不超过 13 秒。
- `FATAL` 表示 Temporal SDK 已取得自动 Stop 所有权；父进程一旦从状态协议观测到它，就不再发送 TERM，
  而是最多等待 2 秒让 child 自行退出，随后直接 `SIGKILL → Wait`。但 context cancel 与尚在 pipe/monitor
  中传递的 FATAL 仍可能竞争；本切片只保证该竞争被限制在可 KILL/Wait 的 child 内，不能据此声称
  SDK Stop/auto-Stop overlap 已消失。C2-4c2b 仍须用确定性 overlap shim 验证 containment，READ claims
  在该证据完成前继续关闭。
- 每个 child 只有一个 goroutine 调用一次 `Wait`；stdout/stderr pipe 的 `WaitDelay` 固定为 500 毫秒，
  防止遗留 FD 无限阻塞 Wait。leader Wait 完成后还必须以 `kill(-pgid, 0)` 得到 `ESRCH` 才能确认原
  进程组消失；Run 不能复用，所有异常只返回固定低敏错误。
- 当前 containment 单元是直接 child 及其原进程组，不是 cgroup：若未来受信代码新增 `setsid/setpgid` 或
  产生脱离进程组的后代，该后代不受 `kill(-pgid)` 或直接 child 的 `Pdeathsig` 约束。C2-4c2b 必须继续
  禁止任意子进程，并把专属 cgroup/PID namespace 作为 READ claim 前的部署门禁；本切片不把进程组测试
  冒充 cgroup 隔离证据。
- 本子阶段的 hidden child 在验证状态 FD 后立即关闭并以固定错误退出，从不发送 READY。两个 Temporal v2
  Dial 仍保持零生产调用，Outbox dispatcher 未安装，READ Admission 继续关闭。

下一切片必须在 child 内完成 Snapshot、PostgreSQL、Starter/Control 两套独立凭据和 Control Worker 的
真实装配；只有 Worker `Start` 成功后才能发送 READY。正常退出顺序必须是 dispatcher → Worker Stop →
Control client → Starter client → PostgreSQL，fatal/panic 路径则不得执行这些进程内 cleanup，而由父进程
强制 containment。

## 角色隔离的 Temporal 控制边界

C2-4c1b 只提供库级角色装配，不把它安装进常驻进程：

- `RuntimeV2StarterClient` 与 `RuntimeV2ControlClient` 是编译期不可互换、不可复制且关闭后永久失效的
  sealed capability。前者只能启动并核验 Workflow，后者只能交给固定 Control Worker；生产 API 不返回
  raw `client.Client`、transport、data converter 或 SDK Worker。
- 两种 client 使用不同固定 identity 和独立连接。窄配置只允许显式 `host:port`、namespace、server name、
  root pool 与客户端证书；TLS 固定为 1.3 双向认证，客户端 key 固定为 ECDSA P-256，禁用系统代理，并在
  拨号前验证 endpoint、证书有效期、ClientAuth EKU、私钥 scalar/公钥/certificate 匹配及调用方存储别名。
  不会自动回退系统根；后续配置 loader 必须仅从 owner-only 显式 CA 文件构造 root pool。API key、header
  provider、interceptor、context propagator、自定义 converter 和任意 gRPC dial option 都没有生产配置入口。
- eager Dial 成功后，每个角色还必须在同一个最长 5 秒 context 中、无应用层重试地调用
  `GetClusterInfo` 与强一致 `DescribeNamespace`。响应必须给出 canonical non-zero cluster UUID、匹配且为
  `REGISTERED` 的 namespace、canonical non-zero namespace UUID 和无控制/格式字符的 cluster name；固定
  domain-separated SHA-256 proof 只保存在不透明 capability 中。相同 endpoint/SNI/root/namespace 但落到
  不同 cluster，或同名 namespace 被重建，都会拒绝后续组装。生产 Temporal 身份因此还需要 cluster
  `System Reader` 与目标 namespace `Reader`；权限、空 ID、旧服务端或 RPC 失败一律 fail closed。
- 承载私钥的临时 `RuntimeV2ClientOptions` 自身对全部 `fmt` 格式固定脱敏并拒绝 JSON 编解码；调用方仍须
  只在启动边界短暂持有它，拨号成功后立即清除原始 key material，不能把该值放进日志、配置快照或审计。
- package-owned v2 data/failure converter 没有可直达 wire 的 SDK 默认 converter fallback。业务 payload 必须恰好一个、JCS canonical、
  `json/plain` 且不超过 4096 字节的 allowlisted History DTO；唯一零 payload 例外是 Temporal SDK 对“无
  error details”的 `nil Payloads` plumbing，非 nil 空对象仍拒绝。未知类型、额外 payload、非 canonical
  JSON、未知/重复字段、非 allowlist error details 和私有 Memo identity 的普通 JSON 序列化全部 fail closed。
  Failure graph 另受 4 KiB/四层深度、固定 failure kind/activity type/application type/retryability 约束；message/source
  被规范为固定低敏值，stack trace、encoded attributes、所有 details、未知 proto 字段、Child/Nexus/Reset kind
  均拒绝。SDK `failureHolder` 的原始 proto 也必须经过同一规范化，非法 graph 固定变成 non-retryable
  `READ_RUNTIME_FAILURE_REJECTED`，当前错误契约不携带 details。
- `RuntimeV2Starter` 只能把 `signal.ingested.v1` 的持久安全 ID 映射为固定 M/R/B 身份和 control queue；新启动
  与 `AlreadyStarted` 都必须完成 exact-run Describe → immutable Started event → Describe 证明后才能让
  Outbox ACK。远端错误与 panic 只返回固定低敏 code。
- `RuntimeV2ControlWorker` 固定注册一个 v2 Workflow、Prepare v2 和 Recovery v1；不能注册 Runner Execute
  Activity，也不接受 queue、registration、`worker.Options`、alias/plugin 或 eager execution。并发度、poller、
  heartbeat throttle、35 秒 stop timeout 和无错误正文的 fatal signal 均由包固定。Prepare/Recovery 在唯一
  注册边界使用 pointer-result adapter：错误返回 `nil,error`，成功才返回 `*DTO,nil`，避免 SDK 在转换错误前
  序列化无效零值 DTO；strict converter 不为该 SDK 行为开放非法结果 fallback。
  包装层不会在持锁时调用 SDK `Start`；并发 `Stop` 只记录意图，待 `Start` 返回后串行清理，且此时
  `Start` 固定返回 rejected，不能把已停止 Worker 发布为运行中。SDK 没有 `Start(ctx)`，内部 namespace
  RPC 的超时不能替代进程级启动预算；C2-4c2 supervisor 必须在独立进程上执行 deadline + hard fail-stop。
- `Snapshot.NewRuntimeV2TemporalRoles` 是唯一跨 package 的高层装配入口。它从 Snapshot 私有 Summary 取得
  M/R/B，要求两个 client 的 HostPort、namespace、server name、完整 cloned root pool 与服务端
  cluster/namespace proof 精确属于同一 Temporal connection binding（客户端证书允许按角色不同），并在
  Snapshot 先用私有 authority/planner 创建未发布的 Activities，再在两个 client 的共享 lifecycle lease 内
  原子比较 connection 并创建、发布 Starter 与 Control Worker；并发 `Close` 只能在这段 client-bound
  组装完成后取得独占 lease，任一失败都不向调用方发布部分结果。调用方不能覆盖 digest、queue、namespace、
  converter、注册集或 Worker options。
- Go 没有 friend package，因此 `investigationworkflow` 的少数低层构造器仍需导出给 `readassembly`；仓库
  仅保留 bound roles 与 Activities 组装所需入口；单独 Starter/Control Worker 构造器及 connection compare
  已降为包私有，外部真实服务测试只能使用 `_test.go` bridge。AST 门禁要求其余生产调用点恰好只存在于
  Snapshot 桥，函数取值/别名同样拒绝，两个 public Dial 在本子阶段必须保持零生产调用。
  Snapshot 的 control Activities 构造器已降为包私有；任何新 `cmd/internal` 绕过都会使测试失败，后续
  supervisor 接入必须显式审查并收窄更新 allowlist。旧的共享角色 v1 `DialTemporalClient`、`NewStarter`
  与 `NewWorker` 已标记 deprecated，并同样被锁为零生产调用，不能成为 plaintext/default-converter fallback；
  `go.temporal.io/sdk/client|worker` 的 raw 生产 import 也被锁定到 `investigationworkflow` 内现有的六个
  审核文件，新增文件默认失败。

固定 identity 字符串不是授权机制。真实部署仍必须为 Starter 与 Control Worker 分配不同证书/凭据及最小
Temporal RBAC；本地 mTLS 和 pinned dev-server 测试不能证明企业 PKI、namespace ACL 或 HA 服务端配置。
一次 deployment probe 也不能约束后续 gRPC reconnect；DNS/VIP 必须只包含同一个 Temporal cluster，不能把
active/standby 或独立 deployment 放在同一名称下，最好再使用 cluster 专属服务端 PKI/SPIFFE 身份。
正常关闭顺序必须固定为 Control Worker `Stop` → Control Client `Close` → Starter Client `Close` →
PostgreSQL 连接关闭。Temporal SDK 在 `OnFatalError` 返回后自行 `Stop`，因此 `Fatal()` 只允许 supervisor
标记进程不健康并按 grace deadline 终止隔离进程，不能因该信号立即再次调用 Worker `Stop` 或关闭 clients；
即使正常人工 `Stop` 已开始，随后与 SDK fatal auto-stop 重叠也没有可由 v1.46.0 公开 API 证明的进程内
无竞态语义。该限制登记为 `C2-4c2 BLOCKED EXTERNAL GATE`：Worker/clients 必须位于独立子进程，父
supervisor 对启动、Stop、fatal、panic 和通知丢失统一执行 deadline、强杀及 `Wait`/reap；在确定性 overlap
shim 证明 containment 前 READ claims 不得开启。任何 fatal/stop 异常都使 rollout 失败，不能报告 graceful success。
后续 READ Runner Worker 注册 Execute Activity 时也必须使用同样的 pointer-result adapter，并以 pinned
dev-server 失败路径证明 `nil,error`；在此之前不得让 Runner 轮询真实 Activity queue。

## 固定协议身份

协议名称和队列均由代码生成，部署配置不能覆盖：

- Workflow：`aiops.investigation.read.v2`；
- preparation Activity：`aiops.investigation.prepare.activity.v2`；
- DB recovery Activity：`aiops.investigation.read-result.recover.activity.v1`；
- Runner Activity：`aiops.investigation.read-task.execute.activity.v1`；
- Workflow Memo：`aiops.investigation.read.identity.v2`；
- control queue：`aiops-investigation-read-v2-<manifest>-<registry>-<bundle>`；
- Runner queue：`aiops-investigation-read-task-v2-<environment UUID>-<deployment SHA-256>`；deployment
  hash 以固定 domain separation 对 manifest、registry、bundle 三摘要计算，队列不暴露原始三摘要。

Workflow ID 必须等于持久 Outbox event ID。Memo 必须恰好包含一个字段，其 `json/plain`
payload 必须与 JCS canonical Workflow input 完全相等。Workflow 拒绝 parent、cron、retry、continue、
search attributes、额外 Memo、非默认 priority、错误 namespace、错误 task queue 和错误 Workflow timeout。

control queue 同时绑定完整 Plan manifest、connector registry 与 atomic Bundle 摘要；Runner queue 绑定
精确 Environment UUID 及这三个摘要的 domain-separated deployment hash，防止另一环境、不兼容 Bundle
或同 Bundle 的旧 Plan Runner 拾取 Task。旧、新 digest Worker 必须按各自 exact queue 共存到对应 Workflow
和 Task 全部终态，不能让请求正文选择 queue、Plan 或 Bundle。

Runner queue v2 是在 C2-4b 协议尚未装配、dispatcher 与 claims 均关闭、没有真实 v2 Workflow History 时
完成的首发前修正，因此不需要对已运行 History 使用 `GetVersion`。任何外部开发环境若曾绕过该门禁持久化
旧实验 History，都必须在隔离 namespace 中清理或显式迁移，不能用新版代码直接 replay 旧 v1 Runner queue。
后续 live assembly rollout 必须先预热新 control 与 Runner exact queues，再让 dispatcher 启动新 Workflow；
旧两类 Worker 要保留到其对应 Workflow/Task 全部终态后才能 drain，不能靠共享队列做版本兼容。

## History allowlist

所有 v2 DTO 使用严格 JSON，拒绝未知、重复、大小写别名、尾随文档和超过 4096 字节的文档。
History 只允许下列事实：

- Outbox、Tenant、Workspace、Signal、Incident、Environment、Service、Investigation、Task、Evidence ID；
- Task position、逻辑 round、aggregate version 和有界状态；
- manifest、registry、profile、tasks、bundle 与 Evidence content SHA-256。

History 不得出现 Signal 正文、TaskSpec/input、connector 查询、target/endpoint、credential role/value、
bearer、lease token、Runner/证书、scope revision、Evidence items、receipt provenance、远端 header/body/error
或 panic 文本。Runner Activity 只返回 `NOT_CLAIMED`、`COMPLETE_ACKNOWLEDGED` 或
`RECOVERY_REQUIRED`；这些状态都不是数据库终态证明。

## 确定性状态机

Preparation 在 disconnected Workflow context 中完成既有幂等持久化，并回读精确 Environment、Service
和最多 12 个连续 Task reference。无活动 Incident 时返回 `NO_ACTIVE_INCIDENT`。

有 Task 时按 position 严格串行执行，每个 Task 最多三个逻辑 round：

1. 在精确 Runner queue 调度一次 Runner Activity；Temporal `MaximumAttempts=1`、
   `WaitForCancellation=true`、`DisableEagerExecution=true`，不允许 SDK 或服务端重发一次性完成正文。
2. 不论 Runner 返回成功状态、错误、超时或无响应，立即在 control queue 调用 DB-only Recovery。
3. 只有 Recovery 的 `COMMITTED` 或 `CONTROL_CANCELLED` 是可信终态；Workflow 只从 Recovery 投影
   Task status、Evidence ID 和 content hash。
4. Runner 报告 `COMPLETE_ACKNOWLEDGED` 而 Recovery 仍为 `PENDING` 时，作为持久事实冲突固定失败。
5. 其余 `PENDING` 等待固定 35 秒后再次 Recovery；仍为 `PENDING` 才进入下一逻辑 round。
6. 三个 round 后仍未收敛，Workflow 以固定 `READ_TASK_PENDING` 失败，不把未知结果伪装成 Task 失败，
   也不修改 PostgreSQL 终态。

普通 Workflow Cancel 不会立即中断一次性 Runner/Recovery 边界。READ orchestration 使用 disconnected
context 继续执行同一个三轮预算；若所有 Task 得到数据库终态，之后才向调用方返回取消。若三轮后仍为
`PENDING`，Workflow 不确认取消，也不伪造终态，而以固定 non-retryable `READ_TASK_PENDING` 失败；该失败
History 是 durable manual-reconciliation handoff。C2-4c 必须监控并告警该 error type，保留 Task/Workflow，
在数据库事实收敛或运维处置后 Reset/重放；该 supervisor 上线前不得开启 claims。Temporal Terminate 仍只
用于有审计的紧急硬停；它不等价于普通 Cancel，后续同样必须由运维恢复流程核对持久 Task。

## READ Runner Activity

生产构造器只接受由 `readrunnerclient.New` 创建且仍可 Claim 的具体 READ mTLS client、完整且不可复制的
`readruntime.Bundle`、精确 Plan manifest digest，以及非空、服从 context 的可信
`readexecutor.BearerSource`。Connector registry digest 必须从 Bundle 自身取得，不能由 Task 或配置另行
提交。测试 fake 只能通过包内私有端口使用；没有 anonymous、unbound Plan、静态 token、credential-free
或 WRITE fallback。

任何 Gateway 请求前，Activity 必须验证输入 Plan/Registry 与进程 Snapshot 完全相等，以及 exact
Workflow/Activity ID、namespace、run ID、Environment/deployment queue、单次 attempt、
timeout/retry/priority 和输入 Bundle digest。Claim 返回的 Descriptor 在 Bundle Prepare 前再次核对
Plan/Registry，不能仅依赖队列路由。
Temporal heartbeat 在这些检查后立即发送，并由独立 5 秒 supervisor 覆盖 Claim、Prepare、Start、Execute
和 Complete；Gateway heartbeat 仅在 Start 后每 10 秒递增发送，二者不能共用定时器。

执行顺序固定为：

1. 用 scheduler-owned safe IDs 和四个 Plan digest Claim 精确 Task；
2. Bundle 仅从 Gateway 返回且与 expected facts 匹配的 Descriptor 准备 one-shot execution；
3. GO 前失败只允许用无 value、固定 5 秒 cleanup context 尝试一次 Release；只有 Release ACK 才返回
   `NOT_CLAIMED`，否则要求 DB Recovery；
4. Start 返回的 opaque capability 转换为不可伪造的 execution start 后才执行固定 HTTP adapter；
5. context cancel、heartbeat `TERMINATE`、heartbeat 错误或 executor 错误都先取消并等待 executor goroutine
   退出，再返回 `RECOVERY_REQUIRED`；
6. Complete 最多调用一次。任何 Complete 错误或未知响应都不得重发 Evidence，由 Workflow 查询数据库。

bearer、Lease、Start capability、Prepared material、Evidence body 和 completion receipt 均不进入 Activity
输出或普通格式化。Activity 返回前必须停止 Temporal heartbeat supervisor、销毁本地 Lease bearer，并在
Start 后确认 executor 已收敛。

## 部署与后续门禁

C2-4b、C2-4c1a 与 C2-4c1b 只能作为库和 testsuite 契约合并。后续 C2-4c 才能在受监督的常驻进程中
加载 Snapshot 和 PostgreSQL repository，按固定关闭顺序持有上述 Temporal roles，安装真实 Outbox
supervisor、`READ_TASK_PENDING` durable-handoff 监控、Gateway callbacks 与 READ Runner，并完成
PostgreSQL 16 + Temporal + mTLS Gateway + TLS 数据源的本地 Signal→Evidence E2E。

即使 C2-4c 完成，以下证据齐备前 Admission 仍必须关闭：真实 context-compliant Bearer provider、
Heartbeat 事务内 Bundle 重新授权、企业 PKI/Temporal RBAC、NetworkPolicy/egress、源侧 DLP、无混版
drain/rollout、replay 与故障演练、以及签名 Go/No-Go。fake 或本地契约测试不能冒充外部验收。
