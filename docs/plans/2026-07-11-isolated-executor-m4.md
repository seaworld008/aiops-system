# 可终止隔离执行器 M4：固定代码、READY/GO 与不确定性收敛

## 目标与状态

M4 建立 WRITE Runner 与单作业 Executor 之间可强制终止、可审计且默认关闭的进程边界，
同时把 READ/WRITE 两个信任域拆成不同二进制和不同镜像。该里程碑只提供隔离底座，
不开始领取写任务，不编译真实动作适配器，也不开放生产写。

M3 control-plane 继续不注入 `StartAuthorizer`；因此即使部署 WRITE 镜像，Gateway 也不会
允许 action start。当前 `cmd/executor` 对所有 mutation handler 都在 READY 前拒绝。
M6 只能在这两个门禁都经过明确改造后接入固定的非生产适配器。

## 固定信任边界

| 产物 | 镜像内容 | 允许的职责 | 明确禁止 |
| --- | --- | --- | --- |
| `aiops-read-runner` | 只有 `cmd/read-runner` | M5 的环境专属只读 Activity | Executor、mutation 包、写任务、写凭据 |
| `aiops-write-runner` | `cmd/write-runner` 与固定 `/usr/local/libexec/aiops-executor` | M6 的类型化非生产动作 | 任意 binary/argv/shell、生产任务、通用工具调用 |
| `aiops-executor` | 仅存在于 WRITE 镜像 | 单作业类型校验和固定适配器执行 | 独立部署、网络控制面、从 payload 选择代码 |

运行镜像基于 `scratch`，使用固定数字 UID/GID `65532:65532`，不包含 shell、包管理器
或调试工具。WRITE 镜像内 Executor 及其父目录由 root 拥有且不可 group/world 写；
非 root WRITE Runner 只能执行它，不能替换它。

## READY/GO 双屏障

父子进程只使用三条匿名 pipe，文件描述符和消息方向固定：

```text
fd 3  parent -> child  PREPARE（无 Secret，含有界类型化 ActionEnvelope）
fd 5  child  -> parent READY / RESULT
fd 4  parent -> child  GO（有界 Secret，一次传递）
```

协议使用有长度上限的二进制 frame 和严格 JSON；拒绝未知字段、重复字段、尾随值、
过深对象和超限正文。Executor 必须先校验 action schema、类型和 handler，成功后才能
返回 READY。PREPARE/READY 还绑定服务端 lease epoch 与 scope revision。父进程只有在
Gateway `:start` 已成功、服务端签发的私有 execution grant 与同一个
job/plan/epoch/scope 完全一致，且凭据状态已经到 `ACTIVE` 后，才可通过 fd 4 写入
Secret 和 GO。公开字段或另一任务的 start 结果不能构造或复用这个 grant。

Secret 不进入 argv、环境变量、工作目录、普通 stdin、stdout/stderr 或日志。WRITE
Runner 与 Executor 在读取任何凭据前均设置并读回验证 `RLIMIT_CORE=0` 和
`PR_SET_DUMPABLE=0`。`no_new_privs` 必须由容器 runtime 在 Go runtime 创建线程前设置，
进程再枚举 `/proc/self/task/*/status` 验证所有线程均为 1；任一失败即退出。子进程只
继承协议 FD，使用空的 `0700` 作业目录和固定环境白名单；stdout/stderr 合计超过
64 KiB 即触发终止，内容始终丢弃而非记录。

当前 M4 Executor 有意没有 mutation handler，所以所有 action 都在 READY 前失败。
这验证了 fail-closed 入口，也防止在 M6 之前通过镜像或运行参数意外获得写能力。

## 终止与状态语义

Linux 子进程使用独立 process group、`Pdeathsig=SIGKILL`，并在 fork/exec 时原子取得
`pidfd`；内核或容器策略不支持 pidfd 时 fail closed。取消、超时、租约失效或协议失败
的固定终止顺序为：

```text
SIGTERM(process group) -> 2 秒 -> SIGKILL(process group) -> 确认无 descendant -> Wait/reap -> 确认 process group 消失
```

Runner 在整个 process group 可证明清空前不会 reap group leader，避免数字 PID/PGID
复用后误杀另一任务。只有直接子进程已被 `Wait` 回收并且整个 process group 确认
不存在，才视为终止完成；不以 signal 发送成功、context 返回或父进程退出推断
“已经停止”。

| 观察点 | 允许的队列结果 |
| --- | --- |
| GO 从未尝试，且整个 process group 已终止并回收 | 可安全 `release` |
| GO 已尝试，包括写入中断或 ACK/RESULT 丢失 | `UNCERTAIN` |
| 超时、强杀、输出洪泛、租约失效或 Executor 崩溃发生在 GO 后 | `UNCERTAIN` |
| 无法确认子进程或 descendant 已死亡 | `UNCERTAIN`，继续持有目标锁 |
| RESULT 有效、子进程正常退出且 process group 消失 | 才能进入 Gateway `complete` / `FINALIZING` |

这条边界不声明副作用是否发生；它只保证模糊结果不会被当成可重试成功，也不会在进程
仍可能存活时释放目标写资格。凭据仍按 M2/M3 的持久吊销流程收敛，吊销完成前保持
`FINALIZING` 和目标锁。

## 启动与配置

`cmd/write-runner` 的 `AIOPS_WRITE_EXECUTION_MODE` 只接受：

- 空值或 `disabled`：不探测 Executor、不领取任务；
- `non-production`：先验证进程 hardening、Linux、pidfd、`/proc`、固定路径、所有权、
  权限和禁止扩权的 xattr/ACL，失败即退出；
- 其他任何值（包括 `production`、`enabled`、`true`）：拒绝启动。

M4 的 `non-production` 也只完成 capability probe 后等待，不领取任务。不存在命令行参数、
payload 或单镜像 `--mode=read|write` 可以切换信任域。

## 镜像与部署约束

镜像定义位于：

- `build/package/read-runner/Dockerfile`
- `build/package/write-runner/Dockerfile`

发布构建必须把 `GO_BUILD_IMAGE` 覆盖为经过 SBOM、签名和漏洞审查的不可变 digest。
CI 的完整版本 tag 仅用于可重复的合入验证，不是发布凭据。

M4 的 process group 不是完整容器沙箱。以下能力仍是进入真实非生产演练前必须由目标
Linux/Kubernetes 环境提供并留存证据的外部门禁：每作业 cgroup v2、审核过的
seccomp/AppArmor（或 SELinux）配置、只读根文件系统与专用 `/tmp` tmpfs、READ/WRITE
NetworkPolicy、独立 ServiceAccount/CA/Vault role，以及禁止 swap/core dump 的节点基线。
在这些证据完成前不得把 `non-production` 理解为可部署到生产环境。

运行和镜像验证步骤见[隔离 Runner 镜像与 Linux 运行门禁](../operations/isolated-runner-runtime.md)。

## 测试出口

- 单元协议：严格 frame/JSON、READY 前拒绝、GO 后 handler 错误与 panic 均收敛为
  `UNCERTAIN`，Secret buffer 使用后销毁；
- Linux 进程：忽略 TERM、fork descendant、结果后挂起、无结果退出、输出洪泛、GO
  前后取消与强杀，均验证 `Wait`/reap 和 process-group 消失；Runner 作为 child
  subreaper 只按 PGID/PPID/zombie 状态回收已收养后代；
- 依赖边界：`cmd/read-runner` 依赖图不得包含隔离执行、凭据或 mutation 包；
- 镜像边界：CI 导出文件系统，验证 READ/WRITE 产物互斥、无 shell、非 root、固定入口；
- 配置边界：只读根 + 由 FD/mount ID 绑定验证的 16 MiB、`0700`、
  `rw,nosuid,nodev,noexec` `/tmp` tmpfs 下 `non-production` capability probe 保持运行；
  缺失或不安全的 `/tmp` 在启动时非零退出，镜像本身不包含 `/tmp`，且 `production`
  必须非零退出；验证后的 `/tmp` FD 保留并用于 `mkdirat` 创建每作业目录；
- 全仓门禁：race、shuffle、vet、五个入口构建、真实 PostgreSQL/Vault 与 vulnerability
  scan 全部通过。

macOS/Windows 只做交叉编译；隔离行为必须在 Linux CI 和目标集群复验，不能用本地
非 Linux 结果替代。

## 回滚

M4 不新增数据库迁移。回滚时保持 M3 Gateway 的 job start 门禁关闭，先停止并 drain
所有 M4 WRITE Runner，再回滚镜像；不得通过恢复单一 Runner 镜像或放宽固定路径校验
来恢复可用性。任何已进入 GO 的任务必须先保持 `UNCERTAIN`、完成进程终止确认和凭据
吊销，不能因镜像回滚释放目标锁。
