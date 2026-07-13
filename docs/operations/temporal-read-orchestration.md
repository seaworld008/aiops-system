# Temporal READ investigation orchestration

阶段：M5C2-4b / M5C2-4c1a / M5C2-4c1b / M5C2-4c2a / M5C2-4c2b0 / M5C2-4c2b1a / M5C2-4c2b1b0 / M5C2-4c2b1b1 / M5C2-4c2b1b2a / M5C2-4c2b1b2b（版本化只读编排、
Plan-bound Runner 路由、角色隔离的 Temporal 控制边界、fail-closed 子进程 containment 与预装配
进程逃逸静态门禁；真实 Worker/Outbox/Runner 尚未装配，READ claims 关闭）

本阶段把既有 investigation preparation、持久 READ Task、mTLS Gateway、结果恢复和 atomic
runtime Bundle 连接成可 replay 的 Temporal v2 协议，并由不可互换的 Starter/Control Client、严格
converter、sealed Starter/Control Worker 和 Snapshot 高层工厂封闭控制侧装配边界。C2-4c2a 只把
`cmd/worker` 变成固定 self-reexec 父监督器；它不装配 Temporal、PostgreSQL 或 Outbox，隐藏 child 会在
READY 前固定失败。该切片不修改配置、Outbox dispatcher、Gateway Admission、迁移或业务 HTTP API。Control Plane 仍安装关闭态
Admission，生产代码仍没有打开 READ claims 的构造器；WRITE claims 与 production write 也继续不存在
启用路径。C2-4c2b0 让父监督器在 TERM grace 内继续处理晚到 FATAL，并把“受信 child 代码不得创建
或逃逸到另一进程组/namespace”固化为仓库静态门禁；它仍不安装任何 live 依赖或打开 Admission。
C2-4c2b1a 只新增固定根 public-source snapshot 与 sealed memfd capability。C2-4c2b1b0 将它以唯一固定
FD4 交给 contained child，并在 child 内重复验证 descriptor、frame、工件闭包与证书。C2-4c2b1b1 再从
同一次验证捕获的四份 manifest 与 target CA 闭包构造真实语义 Snapshot，完整比较
`expected_snapshot`。C2-4c2b1b2a 再加入非 READY 的 `SECRET_READY`、固定 FD5–FD7 和证书私钥绑定；
C2-4c2b1b2b 将独立 tmpfs 固定根的 secret-loader 安装为生产 supplier，并证明取消、deadline、后代与
异常退出均同步 kill/reap。runtime factory 仍固定不可用，因此不 Dial、不 READY。

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
  而是最多等待 2 秒让 child 自行退出，随后直接 `SIGKILL → Wait`。C2-4c2a 中 context cancel 与尚在
  pipe/monitor 中传递的 FATAL 仍可能竞争；C2-4c2b0 已让父进程在发出 TERM 后继续消费状态、退出和输出
  事件。若 FATAL 在 TERM grace 内到达，父进程不会再次发送 TERM，而会把剩余窗口收窄为 2 秒异常
  containment，再 `SIGKILL → Wait/reap`。TERM 无法撤回，因此这证明的是竞态被确定性限时收敛，不能
  据此声称 SDK Stop/auto-Stop overlap 已在进程内消失。
- 每个 child 只有一个 goroutine 调用一次 `Wait`；stdout/stderr pipe 的 `WaitDelay` 固定为 500 毫秒，
  防止遗留 FD 无限阻塞 Wait。leader Wait 完成后还必须以 `kill(-pgid, 0)` 得到 `ESRCH` 才能确认原
  进程组消失；Run 不能复用，所有异常只返回固定低敏错误。
- 当前 containment 单元是直接 child 及其原进程组，不是 cgroup：若未来受信代码新增 `setsid/setpgid` 或
  产生脱离进程组的后代，该后代不受 `kill(-pgid)` 或直接 child 的 `Pdeathsig` 约束。C2-4c2b0 已把
  任意子进程与已知进程组/namespace 逃逸 primitive 设为仓库静态拒绝项；专属 cgroup/PID namespace 仍是
  READ claim 前的部署门禁，不能用进程组测试或源码扫描冒充该外部隔离证据。
- 本子阶段的 hidden child 在验证状态 FD 后立即关闭并以固定错误退出，从不发送 READY。两个 Temporal v2
  Dial 仍保持零生产调用，Outbox dispatcher 未安装，READ Admission 继续关闭。

## C2-4c2b0 预装配 overlap 与进程逃逸门禁

C2-4c2b0 在真实 Temporal/数据库能力进入 child 之前收紧仓库架构扫描：生产 Go 文件不得在已审查的
`workerprocess`/`isolatedexec` 路径之外导入 `os/exec`，也不得直接调用或把 `os.StartProcess`、
`syscall`/`x/sys/unix` 的 `ForkExec`、`Exec`、`StartProcess`、`setsid`、`setpgid`、`clone`、
`unshare`、`setns` 保存为函数值，也不得通过 `SysProcAttr.Setsid/Cloneflags/Unshareflags` 绕过；相关包的
dot import 同样拒绝。`SYS_FORK`、`SYS_VFORK`、
`SYS_CLONE/CLONE3`、`SYS_EXECVE/EXECVEAT`、`SYS_SETSID`、`SYS_SETPGID`、`SYS_UNSHARE`、
`SYS_SETNS` 等进程创建、脱组或 namespace raw syscall 常量也不能进入未审查生产代码。全仓对
`syscall`/`x/sys/unix` 的 `Syscall*`、`RawSyscall*` 入口执行默认拒绝检查：直接数字、运行期计算值、
无法静态解析的编号，或不匹配精确 `file + entrypoint + constant` 清单的调用都会失败。fixture 同时覆盖
import alias、函数值 alias 与 dot import，避免只拦截表面上的直接调用。

门禁精确保留现有 fd-bound `FLISTXATTR`、Darwin `fgetattrlist(228)`、固定 `PRCTL` hardening，及 Linux
父监督器和隔离执行器已经审查的 `SysProcAttr.Setpgid`、进程组 `kill` 与 `PR_GET_PDEATHSIG` 指针 ABI
读取；这些调用只读取文件安全元数据或建立/验证既有 containment，不授予 child 创建后代、脱离进程组
或切换 namespace 的能力。父监督器的唯一生产 `SIGTERM` 发送点也由精确 AST callsite 固定。该门禁是
源码层防回归，不分析运行中动态注入代码，也不证明 cgroup/PID namespace、seccomp 或 LSM 策略已经部署。

C2-4c2b0 的 deterministic overlap shim 固定执行 `READY → TERM/normal Stop 已进入 → FATAL/auto-Stop
挂起`，并以唯一 TERM 状态迁移/AST callsite 和辅助进程标记证明父进程不会重复 TERM、按异常窗口强杀、
单次 Wait/reap 且原 PGID 消失；反向顺序仍保持
“已观察 FATAL 后不发 TERM”。该证据关闭了父监督器停止消费晚到 FATAL 的缺口，但不证明 Temporal SDK
内部 Stop 并发安全，也不替代真实 child、cgroup/PID namespace 或企业 Temporal 环境证据。因此 READ
Admission 继续关闭，hidden child 默认继续在 READY 前失败。

同一切片在 `cmd/worker` 内加入 sealed、package-private 的预装配生命周期仲裁器；它只接受固定的
`Start/Stop/Fatal/FatalQuiesced` 窄接口，不公开 runtime、factory、状态 FD 或退出 seam。FATAL watcher
必须在 `Start` 之前武装，只有 `Start` 成功且未见 FATAL/取消才能报告 READY；正常 context stop 最多
调用一次 `Stop`。
FATAL 在 `Start`、READY 前或 `Stop` 期间到达时，唯一生产 status wrapper 直接调用无 defer 的
`ExitControlWorkerFatal`，不再调用 Stop 或关闭其他资源。测试 seam 返回后也只能得到固定低敏 fatal
结果，不能继续 READY/Close。runtime 一旦创建，仲裁器不再显式关闭 status FD；正常 Stop 后由 child
进程退出关闭它，避免“Close 抢先、F frame 丢失”。此外，正常 exit 0 必须等待 runtime 的独立
`FatalQuiesced` 证明：该 channel 只能在 Stop 返回且已经证明当前及未来都不可能再触发 fatal callback 后
关闭；若证明缺失或不关闭，child 必须保持等待，让父进程 deadline 强制 containment。只有 runtime 尚未
创建的固定 unavailable/预取消路径可以显式 Close。Temporal SDK v1.46.0 目前没有可直接满足该证明的
公开 API，因此当前固定 runtime factory 仍返回 assembly unavailable；这些规则只是为下一切片封住装配
形状，不会产生 Temporal Dial 或 READY。

C2-4c2b 后续装配切片必须在 child 内完成 PostgreSQL、Starter/Control 两套独立凭据和 Control Worker 的
真实装配；只有 Worker `Start` 成功后才能发送 READY。正常退出顺序必须是 dispatcher → Worker Stop →
Control client → Starter client → PostgreSQL，fatal/panic 路径则不得执行这些进程内 cleanup，而由父进程
强制 containment。

## C2-4c2b1a 固定根 public-source capability

`internal/workerbootstrap.OpenProductionSource` 没有参数，也不读取环境变量；唯一生产根固定为
`/run/aiops/control-worker/v1`。Linux loader 从 `/` 开始逐级 `openat + O_NOFOLLOW`，要求祖先只由 root
或当前 euid 拥有且不可被 group/world 写，最终 `v1` 与 `target-roots` 必须为当前 euid 的 `0700`。固定
工件必须是当前 euid 的 `0400` regular file、`nlink=1`，不得带 POSIX ACL、`user.*` 或其他扩权 xattr；
每个 FD 以前后 stat、两次有界 `pread` 和字节比较取得稳定快照，最后重新走完整目录链并核对 inode。

`bootstrap.json` 使用严格 `control-worker-public-source.v1`，只允许：调用方声明的 `expected_snapshot`
六摘要、PostgreSQL/Temporal 非秘密 endpoint、九个固定工件的 raw SHA-256，以及排序唯一的 target CA
内容摘要。四份 manifest、PostgreSQL root/client certificate、Temporal root/starter/control certificate
与 target manifest 实际引用的全部 `target-roots/<sha256>.pem` 必须形成无遗漏、无额外项的闭包；客户端
证书只允许当前有效的 P-256 ClientAuth 链，三张 leaf/public key 必须不同，证书文件不得包含 private key。
原始工件累计最多 5 MiB，JSON/frame 最多 8 MiB，避免大量 target root 在最终大小检查前造成放大分配。

成功后 loader 只发布不可复制、不可 JSON 序列化、固定脱敏的 `PublicSourceCapability`：内容被装入
domain-separated digest frame，再写入 `MFD_CLOEXEC|MFD_ALLOW_SEALING` memfd，施加
`F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`，并重新以 `O_RDONLY|CLOEXEC` 打开；最终验证
tmpfs regular inode、`nlink=0`、owner/mode/size、完整 seals 和只读 access mode。非 Linux 固定失败。

这里的 `Source` 是关键边界：`expected_snapshot` 是部署方声明，不是已经验证的 Snapshot proof；b1a
只证明受信来源、完整闭包与不可变传输，不调用四个既有语义 loader，也不构造 `readassembly.Snapshot`。
仓库 AST 门禁只允许 `internal/workerprocess/platform_linux.go` 作为生产 consumer，并精确固定
`OpenProductionSource` 与 `AcceptInheritedSource` 各一次直接调用。C2-4c2b1b1 只有从同一 envelope 构造
真实 Snapshot 并精确比较完整 Summary 后，才可进入 secret-ready 阶段；任一语义错误都必须在
Dial/READY 前失败。Starter/Control/PostgreSQL 的证书不同也不等于企业 PKI profile、Temporal RBAC 或
数据库授权已经隔离；这些仍是外部 Go/No-Go 门禁。

当前 capability 已进入固定 FD4 并完成语义 Snapshot 比较；父进程同时预建空的 FD5–FD7 匿名 pipe，只有
child 发出非 READY 的 `SECRET_READY` 后才允许调用 supplier。生产 supplier 已固定为下一节的独立
secret-loader；child 仍对三份有界 role frame 做完整性、精确 EOF、P-256 PKCS#8 与 FD4 client certificate
SPKI 绑定校验。固定 runtime factory 仍不可用，因此不创建 PostgreSQL pool，不执行 Temporal Dial、不安装
Outbox，也不发送 READY。

## C2-4c2b1b0 固定 FD4 与 child 独立复验

固定根读取先在一个短生命周期、空环境、独立进程组且带 `Pdeathsig=SIGKILL` 的 public-source loader
child 内完成。loader 只通过固定 FD3 匿名 pipe 输出最多 8 MiB 的公开 frame；父进程在
`workerbootstrap` 内有界接收、独立复验并重建 sealed memfd。整个 loader 读取、传输、退出与 PGID 清空
共同占用启动预算；超时或取消会关闭 pipe，在 pidfd 钉住且 leader 尚未 reap 时强杀并确认原 loader
进程组无其他成员，最后执行唯一 `Wait`，避免裸 PID/PGID 复用误杀。因此阻塞的 FUSE/CSI/NFS 读取不会
冻结常驻父进程。pidfd 证明或确认窗口本身失效时不会在当前 goroutine 进入无界 Wait，而是返回未确认
fail-stop，并仅安排唯一后台 reaper；`cmd/worker` 随即退出，Pdeathsig 继续约束 loader。该 loader 不接收
任何秘密，FD4 仍只用于后续 control child。

父监督器启动 control child 时，`ExtraFiles` 必须恰好是 `[statusWriter, publicSource]`：FD3 仍是
child→parent 的只写状态 pipe，FD4 只能是 parent→child 的只读 sealed memfd。
`PublicSourceCapability.StartChild` 在 Linux 先完整核验固定 `/proc/self/exe`/隐藏参数、空环境、根目录、
无 stdin、同一有界输出 sink、500 毫秒 WaitDelay、精确 Setpgid/Pdeathsig/pidfd 及 FD3 pipe，再自己安装
FD3/FD4 并调用一次 `Start`；它不会把 source `*os.File` 交给回调或保留在返回后的 `exec.Cmd`。`Start`
返回后无论成功、失败或 panic 都关闭父句柄并永久消费 capability。Start、Close 和重复启动互斥；若启动后的任何清理失败，父进程会强杀整个原 PGID、有界
`Wait` 并验证进程组消失，不能把半装配进程或同组后代交给 supervisor。

child 在接受状态 FD3 后，只从固定 FD4 取得 source，不接受调用方传入 FD、path 或 bytes。它设置并复验
`CLOEXEC`，要求 FD4 是当前 euid 拥有的 tmpfs regular inode、`0400`、`nlink=0`、`O_RDONLY`、8 MiB
以内且四类 seal 精确齐全；前后 `fstat` 必须稳定。随后使用有界 `pread` 重验 magic、长度、domain-separated
SHA-256、严格 JSON、固定 artifact 顺序/名称/摘要、5 MiB source 预算、target CA 闭包及三套当前有效且
互异的公共 client certificate。缺失、交换、普通文件、pipe、可写或少 seal 的 memfd，frame 截断/尾随、
未知字段、非规范 JSON、角色或摘要替换都会在 READY/Dial 前失败。child 同时拒绝 FD5 及以上任何额外
非 `CLOEXEC` 继承能力。

成功后 child 只得到不可复制、不可序列化且固定脱敏的 `InheritedSource` 生命周期 capability；原始字节不
对 runtime 层公开，source 由 `ChildStatus` 持有，并在 READY 写失败或正常关闭时一并关闭。C2-4c2b1b0
到此只证明 FD4 传输后的不可变工件集合；C2-4c2b1b1 才增加下一节的语义证明。固定 runtime factory 仍返回
assembly unavailable，因此 hidden child 会在 READY 前退出；FD5 及以上、秘密读取、PostgreSQL/Temporal
连接、Outbox、Gateway Admission、READ/WRITE claims 和所有生产写状态均未改变。

## C2-4c2b1b1 同一 envelope 的语义 Snapshot

FD4 首次验收时，child 从已经通过 frame、artifact、target CA 与证书验证的同一 canonical envelope 私存
四份 manifest、target CA 的精确 `Path+Contents` 闭包及 `expected_snapshot`。它不重新读取固定根，也不把
path、FD、raw bytes、artifact map、expected digest 或 resolver 暴露给 `cmd/worker`。`BuildSnapshot` 只能
调用一次；开始后即取走私存材料，成功、错误、取消、panic 都清零全部 backing，失败还会关闭 source 并
永久拒绝重试。

语义编译复用 Connector、Plan、Target、Egress 既有 strict decoder 与构造器。Target 的 canonical 路径
不会调用 `securemanifest.Load`，而是只从捕获闭包解析 CA；任何 root 缺失、额外、重复或路径不匹配都会
拒绝。实际 Plan/Registry/Profile/Bundle 摘要由构造结果重新计算，再与 bootstrap 的 schema 和六个摘要
完整精确比较；artifact SHA 或部署声明本身都不能自证。Snapshot 发布后不保留 manifest、root、source 或
expected backing。

`workerprocess.BuildControlWorkerSnapshot` 是 `cmd/worker` 进入该证明的唯一桥，并把 `ChildStatus` 标记为
已装配；状态协议在标记前拒绝 READY。仓库 AST 门禁把高层 canonical bridge、四个技术可见的内存编译
入口和 `BuildSnapshot` 各锁定到唯一直接调用点，拒绝 import alias 与函数值旁路。当前
`newControlChildRuntime` 对有效 Snapshot 仍固定返回 assembly unavailable，所以本切片没有密码、private
key、DSN、PostgreSQL/Temporal Dial、Worker Start、Outbox、Admission 或 claims；下一步是 b1b2 的非
READY secret-ready barrier 与 FD5/FD6/FD7 一次性秘密协议。

## C2-4c2b1b2a `SECRET_READY` 与固定 FD5–FD7

父监督器在 `Start` 前创建三组空匿名 pipe，并由唯一 `StartChild` 按
`[FD3 status writer, FD4 sealed public source, FD5 PostgreSQL reader, FD6 Temporal Starter reader, FD7 Temporal Control reader]`
固定映射给 child；请求、环境、argv 和 payload 都不能选择或替换 descriptor。child 独立要求 FD5–FD7 为
互不相同的只读 FIFO，并与 FD3/FD4 inode identity 不同；设置 `CLOEXEC` 后拒绝 FD8 以上任何额外
non-CLOEXEC capability。

状态协议固定为 `Snapshot → S → secret bind → future R`。`S` 不是 READY，只能发送一次；`R` 前置、`SS`、
`SRS`、未知字节或非终态 EOF 都是协议破坏。父进程只在收到 `S` 后调用固定 supplier，supplier 使用最初
30 秒启动预算的剩余时间，不能重置 deadline。异常、取消、超时、FATAL、输出洪泛或 child 退出会先关闭
全部 secret writer，再沿既有 PGID/pidfd 路径终止并 `Wait`/reap。

每条 secret pipe 只接受一个不超过 2104 bytes 的 domain-separated 二进制 frame：固定 magic/version/role、
reserved zero、big-endian 长度、SHA-256 和精确 EOF。PostgreSQL frame 包含有界密码与 canonical 未加密
PKCS#8，两个 Temporal frame 各只含对应角色 PKCS#8；三者均只接受 ECDSA P-256，并必须与 FD4 首次捕获的
对应 client certificate SPKI 常量时间精确匹配。三条全部成功后才原子发布包内 opaque bundle；失败、取消
与 Close 会清空 owned buffer 并永久消费 capability。Go heap 与加密库内部复制不构成物理内存清零证明，
部署仍需 dump/ptrace、swap 与节点内存控制。

b1b2a 先只证明 transport/barrier；b1b2b 已按下一节把生产 supplier 固定为受 containment 的
secret-loader。`newControlChildRuntime` 仍固定 unavailable，因此当前仍是零 PostgreSQL/Temporal Dial、
零 Worker Start、零 READY、零 claims。

## C2-4c2b1b2b 独立固定根 secret-loader

生产 Secret 根固定为 `/run/aiops/control-worker-secrets/v1`，不位于公共
`/run/aiops/control-worker/v1` 之下，也不存在 fallback 或交叉读取。该根必须位于 tmpfs；祖先必须由 root 或当前
euid 拥有且不可被 group/world 写，最终 `v1` 必须为当前 euid 的精确 `0700`。四个固定 `0400`、当前
euid、`nlink=1` regular file 分别是 `postgres-password`、`postgres-client-private-key.pkcs8`、
`temporal-starter-private-key.pkcs8` 和 `temporal-control-private-key.pkcs8`。POSIX ACL、`user.*`、未知
xattr、symlink、hardlink、FIFO、device、普通磁盘文件、空文件和超限文件全部拒绝。部署不能直接使用
Kubernetes Secret 的 symlink/`..data` 投影；必须由受控初始化步骤复制到独立 memory-backed `emptyDir`
或提供同等 inode/mode/owner/tmpfs 证明的 CSI mount。

loader 先打开并验证全部四个固定文件，再对每个已钉住 FD 做前后 stat 与两次有界 `pread`，重开完整目录
链核对 root identity；只有密码、三份 canonical ECDSA P-256 PKCS#8 和三把互异公钥全部通过后才编码任何
输出。三帧沿用 b1b2a 的固定 role/magic/version/长度/domain-separated SHA-256 协议且各自小于
`PIPE_BUF`。loader 直接将 PostgreSQL、Temporal Starter、Temporal Control 帧写到自身固定 FD3、FD4、
FD5；父进程只转交三个互异的 `O_WRONLY` 匿名 FIFO，并在 `Start` 后立即关闭自己的 writer，不读取、解析、
缓冲或记录任何 Secret 字节。control child 继续在固定 FD5–FD7 上独立验证 role、精确 EOF 和证书 SPKI，
所以交换 writer、截断、重复 key 或部分写不会发布 bundle。

secret-loader 使用独立隐藏参数、固定 `/proc/self/exe`、空环境、`cwd=/`、nil stdin、丢弃 stdout/stderr、
独立 PGID、`Pdeathsig=SIGKILL` 和 pidfd；调用方不能传 path、argv、env、文件名、role 或额外 FD。它只在
合法且唯一的 `S` 后启动，并占用最初 30 秒 startup deadline 的剩余预算。成功必须同时证明 pidfd 可信
退出、原 PGID 无成员、唯一 `Wait` 成功、pidfd 关闭且进程组消失。取消、超时、panic、读取/写入失败、
非零退出或 surviving descendant 都会整组 `SIGKILL` 并同步回收；异步 supplier operation 在 supervisor
返回前必须 cancel/join，不能遗留后台 loader。PGID 仍不能证明恶意后代没有 `setsid` 逃逸，因此真实 claims
之前的每作业 cgroup/PID namespace、seccomp/LSM 和网络隔离仍是外部门禁。

本切片没有 PostgreSQL/Temporal Dial、Worker Start、READY、Outbox dispatcher 或 READ claims；下一切片
只能在同一 contained control child 内装配真实客户端/runtime，并继续由关闭态 Admission 阻止任务推进。

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
supervisor 对启动、Stop、fatal、panic 和通知丢失统一执行 deadline、强杀及 `Wait`/reap。C2-4c2b0 已用
确定性 overlap shim 证明父进程 containment，但真实 Worker 尚未进入 child，cgroup/PID namespace 与企业
环境证据也未完成，READ claims 仍不得开启。任何 fatal/stop 异常都使 rollout 失败，不能报告 graceful success。
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

`collected_at` 是连接器/Runner 提交的来源时间，不作为服务端审计时钟。控制面仅允许它相对数据库持有的
Task `started_at` 与接收时间偏差不超过固定 2 秒；超出即拒绝并把 Runner 视为时钟不健康。
Evidence `created_at` 与 receipt `received_at` 均由 PostgreSQL 覆盖生成，作为排序和审计的可信时间。
`000014_read_evidence_clock_skew` 同时在数据库触发器和 CHECK 约束中执行该边界；若仍存在来源时间晚于
服务端创建时间的 Evidence，down migration 必须拒绝回滚。

bearer、Lease、Start capability、Prepared material、Evidence body 和 completion receipt 均不进入 Activity
输出或普通格式化。Activity 返回前必须停止 Temporal heartbeat supervisor、销毁本地 Lease bearer，并在
Start 后确认 executor 已收敛。

## 部署与后续门禁

C2-4b、C2-4c1a 与 C2-4c1b 只能作为库和 testsuite 契约合并。后续 C2-4c 才能在受监督的常驻进程中
加载 Snapshot 和 PostgreSQL repository，按固定关闭顺序持有上述 Temporal roles，安装真实 Outbox
supervisor、`READ_TASK_PENDING` durable-handoff 监控、Gateway callbacks 与 READ Runner，并完成
PostgreSQL 18.4 或更新的 18.x + Temporal + mTLS Gateway + TLS 数据源的本地 Signal→Evidence E2E。

即使 C2-4c 完成，以下证据齐备前 Admission 仍必须关闭：真实 context-compliant Bearer provider、
Heartbeat 事务内 Bundle 重新授权、企业 PKI/Temporal RBAC、NetworkPolicy/egress、源侧 DLP、无混版
drain/rollout、replay 与故障演练、以及签名 Go/No-Go。fake 或本地契约测试不能冒充外部验收。
