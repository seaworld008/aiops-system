# 生产规划版本基线

> 核验日期：2026-07-14。此文件锁定实施计划使用的兼容性基线，不表示可以跳过 lockfile、容器 digest、SBOM、升级演练或阶段验收。

## 运行时与平台

| 组件 | 规划基线 | 核验来源 |
|---|---:|---|
| Go | `1.26.5` | [Go release history](https://go.dev/doc/devel/release) |
| PostgreSQL | `18.4` | [PostgreSQL 18.4 release notes](https://www.postgresql.org/docs/release/18.4/) |
| Node.js | `24.x LTS` | [Node.js releases](https://nodejs.org/en/about/previous-releases) |
| pnpm | `10.34.0` | [pnpm package](https://www.npmjs.com/package/pnpm) |
| Temporal Go SDK | `1.46.0` | [Temporal Go SDK releases](https://github.com/temporalio/sdk-go/releases) |
| AWX Controller | `24.6.1` | [AWX 24.6.1 release](https://github.com/ansible/awx/releases/tag/24.6.1) |
| HashiCorp Vault | `2.0.3` | [Vault 2.0.3 release notes](https://developer.hashicorp.com/vault/docs/updates/release-notes#vault-2-0-3) |
| Keycloak Server | `26.6.3` | [Keycloak downloads](https://www.keycloak.org/downloads.html) |
| Browser OIDC client | `keycloak-js 26.2.4` | [keycloak-js package](https://www.npmjs.com/package/keycloak-js) |
| Kubernetes / Kind node | `1.36.2` | [Kubernetes 1.36 release series](https://kubernetes.io/releases/1.36/) |

Keycloak Server 与 `keycloak-js` 是两个独立发布物，版本号不要求相同。计划、测试栈和文档必须使用上表的明确名称，禁止只写含糊的“Keycloak 26.2.4”。AWX `24.6.1` 固定 Personal Access Token/self-service RBAC、Job Template 与 survey/launch API 的首个真实兼容面；Vault `2.0.3` 固定 KV v2、Transit、Database secrets engine 与 lease lookup/synchronous revoke 的首个兼容面。两者的生产 OCI image 必须在实施时解析并锁定架构对应 digest，禁止只保留 tag 或 `latest`。

## Web 工程

| 组件 | 规划基线 |
|---|---:|
| React | `19.2.7` |
| TypeScript | `7.0.2` |
| Vite | `8.1.4` |
| TanStack Router | `1.170.17` |
| TanStack Query | `5.101.2` |
| TanStack Table | `8.21.3` |
| React Hook Form | `7.81.0` |
| Zod | `4.4.3` |
| radix-ui | `1.6.2` |
| lucide-react | `1.24.0` |
| openapi-typescript | `7.13.0` |
| Vitest | `4.1.10` |
| Testing Library React | `16.3.2` |
| MSW | `2.15.0` |
| Playwright | `1.61.1` |
| axe-core / @axe-core/playwright | `4.12.1` |

React 基线可由 [React versions](https://react.dev/versions) 核验，Vite 8.1 由 [Vite 8.1 announcement](https://vite.dev/blog/announcing-vite8-1) 核验；其余前端包在实施开始时以 npm registry 再核验并由 `pnpm-lock.yaml` 固定。MSW 只允许进入开发/测试依赖和测试 bundle。

## VictoriaMetrics 全家桶

| 组件 | 规划基线 | 核验来源 |
|---|---:|---|
| VictoriaMetrics | `1.147.0` | [VictoriaMetrics releases](https://github.com/VictoriaMetrics/VictoriaMetrics/releases) |
| VictoriaLogs | `1.51.0` | [VictoriaLogs releases](https://github.com/VictoriaMetrics/VictoriaLogs/releases) |
| VictoriaTraces | `0.9.4` | [VictoriaTraces releases](https://github.com/VictoriaMetrics/VictoriaTraces/releases) |
| VictoriaMetrics Operator | `0.73.1` | [Operator releases](https://github.com/VictoriaMetrics/operator/releases) |

这些版本只定义 Provider/CRD/查询契约的首个兼容矩阵；生产部署还必须按平台架构固定不可变镜像 digest，并验证升级、降级、备份恢复和混合版本行为。

## 资产发现 Provider SDK

以下 tag 已在核验日通过 Go module version 查询确认存在；它们是 Phase 1 首个适配器实现基线，不代表共享通用 Provider 权限：

| Provider | Module baseline |
|---|---|
| VMware vSphere | `github.com/vmware/govmomi v0.55.1` |
| Proxmox VE | `github.com/luthermonson/go-proxmox v0.8.0` |
| OpenStack | `github.com/gophercloud/gophercloud/v2 v2.13.0` |
| AWS | core `v1.42.1`、config `v1.32.29`、EC2 `v1.316.0`、STS `v1.44.0` |
| Azure | `azidentity v1.14.0`、`armcompute/v7 v7.3.0` |
| Google Cloud | `cloud.google.com/go/compute v1.64.0` |

每个 SDK 必须被封装为只含固定身份探测和 inventory list/get 的窄接口；Provider SDK 的其他方法存在，不表示系统拥有对应 Capability。升级前必须重新执行静态调用图、真实协议、分页/checkpoint、权限、DLP、HA fence、限流和 soft-stale/restore 测试。

## 变更规则

- 实施任务先按这里的版本创建 manifest、lockfile 与测试环境，不得使用浮动 `latest`、宽松主版本或未固定容器标签。
- 首次解析依赖后提交 lockfile、Go module 校验、Helm/chart lock、镜像 digest allowlist 和 SBOM；发布证据绑定这些摘要。
- 任一主版本、Keycloak Server/client 组合、PostgreSQL、Kubernetes、Victoria CRD、AWX/Vault exact version、governed AWX patch 或其 OCI digest/SBOM 兼容矩阵变更，必须用独立依赖升级提交、ADR/兼容性说明和真实 E2E/回滚证据更新本文件。
- 发现版本已撤回、存在阻断级漏洞或与目标平台不兼容时，停止阶段实现并先更新基线；不得静默漂移。
