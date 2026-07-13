# AIOps System

[![CI](https://github.com/seaworld008/aiops-system/actions/workflows/ci.yml/badge.svg)](https://github.com/seaworld008/aiops-system/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go)](go.mod)

证据优先、策略治理的智能运维调查与受控执行平台。

[English](README.md) · **简体中文**

> [!IMPORTANT]
> 项目目前处于积极开发的 pre-alpha 阶段。只读调查基础可用于开发和评估；生产写不存在可配置启用路径，在试点计划的全部安全、质量门槛通过前始终保持关闭。

## 为什么需要这个项目

现代运维团队已经拥有指标、日志、Kubernetes、虚机、CI/CD、GitOps 和事故沟通工具，真正缺少的往往是一层可信的治理系统：能够关联事实、解释证据，又不会把生产权限交给大模型。

AIOps System 坚持四条原则：

- **先证据，后结论。** 每个运维事实都必须引用有边界、可追溯的证据。
- **模型只提议，确定性系统做裁决。** CEL 策略、身份、审批、实时状态和签名计划共同约束执行。
- **不确定就停止并对账。** 副作用必须被围栏、验证，绝不盲目重试。
- **最小权限是架构边界。** 只读与写入 Runner 使用不同身份、队列、凭据和网络路径。

## 当前能力

| 领域 | 状态 | 已具备能力 |
| --- | --- | --- |
| 信号接入 | 已实现 | Alertmanager/夜莺作用域验签、幂等与去重基础 |
| 只读证据 | 已实现 | Prometheus、VictoriaLogs、Kubernetes、AWX、Argo CD、GitLab、Jenkins、GitHub Actions 有界客户端 |
| 调查引擎 | 基础已实现 | 持久调查事实、严格 mTLS READ Task Gateway、原子 connector/target/egress/executor Bundle、固定 READ executor/Activity、恢复优先 Temporal v2、immutable Snapshot、角色隔离的 Temporal Starter/Control Worker、可监测 fatal/stop 的子进程 containment、sealed 预装配 child 生命周期仲裁器、可强杀限时的固定根 public-source loader 与 sealed FD4 交接；child 会独立复验不可变 frame，但尚未构造语义 Snapshot，固定 factory 仍阻止 READY，尚无 live Runner/Outbox 装配，非配置化 Admission 在 M5C2-4c 与外部 Go/No-Go 前保持关闭 |
| 身份与策略 | 基础已实现 | Keycloak OIDC、Workspace/Environment RBAC、签名 ActionEnvelope、CEL 三阶段裁决 |
| 执行安全 | 基础已实现 | 精确 Runner scope、持久凭据吊销、TLS 1.3 mTLS Gateway、READ/WRITE 拆分镜像、固定可终止 Executor、目标锁、心跳、取消和对账 |
| 生产自动化 | **关闭** | 仍需固定真实适配器、外部 sandbox/网络门禁、非生产演练与正式 Go/No-Go 审查 |
| Web / ChatOps | 规划中 | React 控制台与飞书流程尚未交付 |

“基础已实现”表示核心契约和可测试实现已经存在，不代表对应连接器或写操作可无人值守地用于生产。

## 架构

```mermaid
flowchart LR
    UI["Web / 飞书 / 告警 Webhook"] --> IN["验签接入与服务映射"]
    IN --> CP["Go 模块化控制面"]
    CP --> PG[(PostgreSQL)]
    CP --> OBJ[(S3 兼容证据存储)]
    CP --> TW["Temporal 工作流"]
    CP --> CEL["CEL 策略引擎"]
    CP --> AI["私有 / 云端模型适配器"]

    TW --> GW["出站 Runner Gateway"]
    GW --> RR["只读 Runner"]
    GW --> WR["拆分 WRITE Runner + 固定 Executor"]
    RR --> OBS["指标 / 日志 / K8s / AWX / CI / Argo"]
    WR --> MUT["类型化 K8s / GitOps / AWX 动作"]

    KC["Keycloak"] --> CP
    VAULT["Vault 短期凭据"] --> RR
    VAULT --> WR
```

首版面向单企业自托管和多 Workspace。PostgreSQL 是领域事实源，Temporal 只负责持久编排；Runner 只通过独立的 TLS 1.3 mTLS Gateway 出站通信。

## 安全模型

唯一允许进入执行层的写入输入，是规范化并签名的 `ActionEnvelope`。它绑定精确目标、参数、观测资源版本、前置条件、验证、补偿、风险、策略版本、凭据范围、幂等键与有效期。

生产写入开始前必须完成：

1. 服务与环境映射结果为 `EXACT`；
2. 签名有效且计划哈希不可变；
3. 计划、凭据、执行三个阶段的当前策略均允许；
4. 非申请人的审批绑定精确计划和目标实时状态；
5. 仅签发单目标、短时凭据，使用前持久 anchor，执行后持久吊销；
6. 全局、环境、连接器和动作 Kill Switch 全部允许；
7. 目标锁和试点期生产全局并发限制生效；
8. 固定隔离 Executor 必须终止并回收后才能 release；执行后验证未完成或结果为 `UNCERTAIN` 时，持续占用锁直到人工对账。

完整契约见[架构蓝图](docs/architecture/implementation-blueprint-v3.md)。

## 快速开始

开发要求：

- Go 1.26.5
- PostgreSQL 18.4 或更新的 18.x（持久化与真实迁移测试）
- 目标生产架构还需要 Temporal、Keycloak、Vault 和 S3 兼容对象存储

使用内存仓储启动开发控制面：

```bash
make test
make vet
make build
make run
```

随后访问：

```text
GET http://localhost:8080/healthz
GET http://localhost:8080/readyz
GET http://localhost:8080/api/v1/session
```

内存模式仅用于本地开发。生产模式未配置 PostgreSQL、作用域 Webhook 密钥和 Keycloak OIDC 时会拒绝启动。可参考 [.env.example](.env.example)，请勿提交真实凭据。

运行真实 PostgreSQL 迁移与仓储测试：

```bash
AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -count=1 ./internal/store/postgres ./internal/execution/postgres
```

安装 Docker/BuildKit 后，可构建物理拆分的 Runner 镜像：

```bash
make runner-images
```

WRITE 镜像默认是 `disabled`；M4 的 `non-production` 只执行 Linux 隔离能力探测，仍不领取任何任务。详见[隔离 Runner 运行门禁](docs/operations/isolated-runner-runtime.md)。

## 文档

- [文档索引](docs/README.md)
- [架构概览](docs/architecture/overview.md)
- [2026 V3 实施蓝图](docs/architecture/implementation-blueprint-v3.md)
- [中小企业内部试点计划](docs/plans/2026-07-10-sme-internal-aiops-pilot.md)
- [M4 隔离执行器设计](docs/plans/2026-07-11-isolated-executor-m4.md)
- [隔离 Runner 镜像与 Linux 运行门禁](docs/operations/isolated-runner-runtime.md)
- [READ Runtime Bundle 与关闭态 Admission](docs/operations/read-runtime-bundle.md)
- [路线图与发布门禁](docs/roadmap.md)
- [历史设计归档](docs/archive/README.md)

## 参与贡献与安全报告

欢迎参与架构评审、连接器开发、威胁建模、测试、文档和边界清晰的功能开发。请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，较大的架构改动应先提交提案。

请勿在公开 Issue 中报告漏洞，请按 [SECURITY.md](SECURITY.md) 私下报告。

## 许可证

项目采用 [Apache License 2.0](LICENSE)。
