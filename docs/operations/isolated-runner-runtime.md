# 隔离 Runner 镜像与 Linux 运行门禁

本文说明 M4 READ/WRITE Runner 镜像的构建、内容验证和非生产 staging 要求。它不是
生产部署清单。M4 的 Gateway action start 仍关闭，WRITE Runner 不领取任务，Executor
也未编译任何 mutation adapter。

## 构建两个独立镜像

开发和 CI 可使用与 `go.mod` 一致的完整 patch tag：

```bash
make runner-images
```

等价的显式命令为：

```bash
docker build \
  --build-arg GO_BUILD_IMAGE=docker.io/library/golang:1.26.5-bookworm \
  --file build/package/read-runner/Dockerfile \
  --tag aiops-read-runner:dev .

docker build \
  --build-arg GO_BUILD_IMAGE=docker.io/library/golang:1.26.5-bookworm \
  --file build/package/write-runner/Dockerfile \
  --tag aiops-write-runner:dev .
```

发布流水线不得使用可变 tag，必须把 builder 替换为内部批准的 digest，并以 commit SHA
或发布版本标记输出镜像：

```bash
GO_BUILD_IMAGE='registry.example.com/build/go@sha256:<64-hex-digest>' \
READ_RUNNER_IMAGE='registry.example.com/aiops/read-runner:<commit-sha>' \
WRITE_RUNNER_IMAGE='registry.example.com/aiops/write-runner:<commit-sha>' \
make runner-images
```

尖括号是占位符，不能直接部署。发布流水线还必须生成 SBOM、扫描 CVE、签名并在准入
策略中只允许输出镜像 digest；这些供应链动作不由当前 Make target 冒充完成。

## 内容与入口验收

两个运行阶段均为 `scratch`、`USER 65532:65532`，没有 shell 或包管理器。应在镜像
签名之前至少核对：

```bash
docker image inspect --format '{{.Config.User}} {{json .Config.Entrypoint}}' \
  aiops-read-runner:dev aiops-write-runner:dev

read_id="$(docker create aiops-read-runner:dev)"
write_id="$(docker create aiops-write-runner:dev)"
docker export --output=/tmp/aiops-read-runner.tar "${read_id}"
docker export --output=/tmp/aiops-write-runner.tar "${write_id}"
docker rm "${read_id}" "${write_id}"
tar -tf /tmp/aiops-read-runner.tar
tar -tf /tmp/aiops-write-runner.tar
```

预期结果：

- READ 只有 `/usr/local/bin/aiops-read-runner`，不得出现 WRITE Runner 或 Executor；
- WRITE 有 `/usr/local/bin/aiops-write-runner` 和
  `/usr/local/libexec/aiops-executor`，不得出现 READ Runner；
- WRITE 镜像本身不得包含 `/tmp`；该路径只能由运行时挂载有界 `0700` tmpfs；
- Executor 及 `/usr/local/libexec` 在容器内为 UID 0 所有，且不可 group/world 写；
- 两个镜像均无 `/bin/sh`、`busybox`、动态下载器或运行时编译器；
- WRITE 默认环境固定为 `AIOPS_WRITE_EXECUTION_MODE=disabled`。

CI 已自动执行内容导出和上述关键断言。人工验收仍应记录最终 digest、SBOM、签名、
扫描时间和准入策略结果。

## Linux capability probe

在与目标节点相同的 runtime、内核和 LSM 配置下运行：

```bash
docker run --rm --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=65532,gid=65532 \
  --env AIOPS_WRITE_EXECUTION_MODE=non-production \
  aiops-write-runner:dev
```

进程会在能力检查成功后等待终止信号；它不会领取或执行动作。检查至少覆盖：

- Linux `/proc/self/status` 和 `/proc/self/fd` 可读，`pidfd_open/pidfd_send_signal` 可用；
- Executor 是固定绝对路径、regular file、单 hardlink、root-owned、可执行且不可
  group/world 写，不含 setuid/setgid、file capability、ACL 或未知 xattr；父目录同样
  root-owned 且不可写；
- 容器 runtime 在 exec 前设置 `no_new_privs`；WRITE Runner 与 Executor 枚举所有线程
  并确认均为 1，且 `CapInh/CapPrm/CapEff/CapAmb` 全为 0，同时读回验证 core hard
  limit 为 0、dumpable 为 0；部署仍必须显式 `drop: ALL`，不得把进程内检查当成
  Runtime 配置替代品；
- UID/GID 为 `65532:65532`；根目录 FD 的 `fstatfs` 与 mount ID 同时证明 root
  filesystem 为只读；启动探针通过同一个 `O_PATH|O_NOFOLLOW` `/tmp` FD 核对目录
  UID/GID、精确 `0700` mode、`fdinfo.mnt_id`、mountinfo 中唯一且 root 与 `/tmp`
  均无传播、`/tmp` 无子挂载的
  `/tmp`、tmpfs 类型与 `rw,nosuid,nodev,noexec`，并通过 `fstatfs` 拒绝超过
  16 MiB 的挂载；
- 探针先以 `mkdirat/fstatat/unlinkat` 验证可写；验证后的目录 FD 与 mount ID 保留在
  Supervisor 生命周期内。所有作业目录经该 FD 创建，在 `Start` 前重新核对路径的
  mount ID 与 inode，清理经 `/proc/self/fd/<retained-fd>` 锚定；任一复核或清理失败
  都保持不确定态；
- Runner 设置并读回 `PR_SET_CHILD_SUBREAPER`。强杀后只回收同一 PGID、`ppid=self`、
  `state=Z` 且不是 direct leader 的已收养后代；direct leader 仍只由对应
  `exec.Cmd.Wait()` 回收，禁止全局 `wait4(-1)`；
- `production`、`enabled`、`true` 等值均立即非零退出。

缺失 `/tmp`、使用宿主目录、错误 owner/mode、重复叠加挂载、危险 mount flag 或超过
16 MiB 的 tmpfs 均在 Runner 等待作业前失败。CI 同时覆盖安全配置保持运行与两组错误
配置立即退出；目标集群仍必须在实际 CRI/内核/LSM 下复验相同证据。

宿主机或 CRI 管理员仍可从容器外修改 mount namespace、内存或进程；这是外部受信运行时
边界，必须由节点隔离和审计控制，不能由容器内 FD 检查对抗。进程内复核负责拒绝误授
capability、传播挂载与容器自身可触发的路径漂移，不宣称抵御已失陷的宿主机。

`non-production` 不是环境标签的替代品。后续 M6 还必须由 Gateway 的可信注册、精确
workspace/environment scope 和服务端 action 属性共同拒绝 `production=true`，不得只
信任 Runner 的环境变量。

## Kubernetes staging 基线

仓库尚未提供可发布的 Runner Deployment；以下片段只是目标集群验收基线，必须与企业
PKI、Vault、task queue 和 NetworkPolicy 一同补全。READ 与 WRITE 必须使用不同
Deployment、ServiceAccount、Client CA、Vault role、镜像 digest 和 NetworkPolicy。

```yaml
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: write-runner
          image: registry.example.com/aiops/write-runner@sha256:<64-hex-digest>
          env:
            - name: AIOPS_WRITE_EXECUTION_MODE
              value: disabled
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: executor-tmp
              mountPath: /tmp
      volumes:
        - name: executor-tmp
          emptyDir:
            medium: Memory
            sizeLimit: 16Mi
```

占位 digest 不能部署。标准 `emptyDir.medium: Memory` 与 `sizeLimit` 只能提供 tmpfs 和
容量边界，Pod API/准入规则本身不能施加 `nosuid,nodev,noexec`，也不能单凭
`runAsUser/runAsGroup` 证明卷根已是 `65532:65532`、`0700`。目标集群必须通过受审计的
RuntimeClass、CRI/CSI 或节点策略实际施加这些属性，再由进程内探针验证；否则此示例会
正确地启动失败，WRITE Runner 必须保持关闭。不得用特权 init container remount 或
`hostPath` 绕过门禁。节点还必须禁止 swap，限制 core dump，并保护休眠镜像和物理内存
采集。

## 尚未由 M4 提供的强隔离

独立 process group、`Pdeathsig` 和强制 `Wait()` 解决的是进程生命周期，不等于完整
sandbox。进入 M6 真实非生产演练前，以下项目必须逐项关闭门禁并保存证据：

- **每作业 cgroup v2**：CPU、内存、PID 和 IO 上限，且终止时确认 cgroup 为空；
- **seccomp**：按 Executor 实际 syscall 生成并审核的 profile，而非永久依赖
  `RuntimeDefault`；
- **AppArmor/SELinux**：限制文件、proc、ptrace、mount 和 capability 边界；
- **只读根**：仅 `/tmp` 使用有界内存卷，禁止 hostPath 和持久工作目录；
- **NetworkPolicy**：READ 只到 Gateway 和只读数据源；WRITE 只到 Gateway、Vault 和
  签名 action 所需的窄目标，不允许通用互联网或跨环境访问；
- **身份拆分**：READ/WRITE ServiceAccount 不共享 token、Client CA、Vault role、
  registry repository 或 node placement policy；
- **运行时取证**：禁止把 core、stdout/stderr、`/proc/<pid>/environ` 或 IPC frame 采集
  到日志系统，调试必须使用受审计的独立流程。

任一项缺失都应保持 `AIOPS_WRITE_EXECUTION_MODE=disabled`。M4 不提供绕过开关。

## 故障与回滚

- capability probe 失败：Pod 必须退出并保持 NotReady；不要改为 root、添加 shell 或
  放宽固定路径/所有权检查；
- READY/GO 绑定失败：另一 job/plan/epoch/scope 的 start grant 必须在 GO 前拒绝；
- READY 前失败：只有确认整个 process group 已死亡并回收后，才可安全 release；
- GO 后或无法确认死亡：上报 `UNCERTAIN`，保留目标锁并继续持久吊销；
- 镜像回滚：先确认 Gateway start 门禁关闭，drain WRITE Runner，再按 digest 回滚；
  不允许新旧 write runner 混合领取任务；
- 应急排障：使用平台审计的 ephemeral debug workload，不给运行镜像增加 shell、SSH
  或包管理器。
