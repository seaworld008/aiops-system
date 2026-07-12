# READ Target Runtime 运维契约

日期：2026-07-11
阶段：M5C2-3a（仅构建期契约，尚未装配网络执行或 READ claim）

## 目的与边界

`internal/readtarget` 把一个 READ 数据源目标编译为进程内不可变能力，
`internal/readruntime` 再把 connector、target 与固定 executor profile 解析成三个服务端摘要。
Repository 只持久化这些摘要及自行计算的 aggregate runtime digest；Task、Runner 请求和
Temporal History 都不能提交或覆盖 endpoint、CA、query、credential、网络策略或摘要。

M5C2-3a 不执行网络请求，不读取 bearer credential，不新增 `cmd/*`、配置、迁移或 Gateway
route，也不注册 Temporal Activity。Control Plane 的 `ClaimsEnabled` 仍为 `false`。

## Manifest schema

文件 schema 固定为 `read-target-manifest.v1`：

```json
{
  "schema_version": "read-target-manifest.v1",
  "targets": [
    {
      "scope": {
        "tenant_id": "10000000-0000-4000-8000-000000000001",
        "workspace_id": "20000000-0000-4000-8000-000000000002",
        "environment_id": "30000000-0000-4000-8000-000000000003"
      },
      "target_ref": "由 BuildTargetRef 生成，不能手写复用",
      "kind": "prometheus",
      "endpoint": {
        "origin": "https://metrics.staging.internal:8443",
        "server_name": "metrics.staging.internal",
        "ca_bundle_file": "/run/aiops-manifests/metrics-ca.pem"
      },
      "credential_role_ref": "内容寻址的 role 声明引用",
      "network_policy_ref": "内容寻址的 egress policy 声明引用"
    }
  ]
}
```

示例中的描述字符串不是可加载值。`target_ref`、`credential_role_ref` 与
`network_policy_ref` 均必须采用 `<安全名称>-v1-<完整 64 位小写 SHA-256>`；名称中出现
auth、secret、token、password、credential、endpoint、URL、host、DSN 等敏感语义会被拒绝。
这些引用只能指向版本化声明或制品，不能放入 Secret、accessor、URL、host 或 bearer 值。

每个 target 只允许 `prometheus` 或 `victorialogs`，并绑定一个精确的
`(tenant_id, workspace_id, environment_id)`。运行时还要求 Task 的 mapping 为 `EXACT`；
Service 约束由 connector registry 继续收窄，target manifest 不能扩大它。

## 内容寻址与不可变性

`BuildTargetRef` 对以下规范事实执行 JCS/SHA-256：

- `read-target-contract.v1` 及冻结的 endpoint、CA、transport、credential、network profile；
- 精确 Tenant、Workspace、Environment；
- connector kind、规范 HTTPS origin、显式 SNI server name；
- 按 DER SHA-256 排序的根证书集合；
- credential role ref 与 network policy ref。

CA 文件路径不进入摘要，证书身份进入摘要。PEM 顺序和证书块之间的空白不改变摘要；scope、
kind、origin/SNI、任一 CA、role ref 或 network policy ref 的变化都会产生新 `TargetRef`。
加载器会重新计算摘要，旧 ref 与新定义混用时整个 manifest 启动失败，不存在同名覆盖、热更新
或部分 fallback。Registry 自身也有排序后的 `read-target-registry.v1` 摘要。

`TaskRuntimeBinder` 只接受 canonical TaskSpec、精确 scope、匹配的 connector registry digest，
并由服务端依次解析 connector、target 和固定 executor profile。输出仅包含
`ConnectorDigest`、`TargetDigest`、`ExecutorDigest`；错误、panic、typed-nil context 与漂移
均折叠为低敏 fail-closed 结果。

## 文件与 CA 要求

Manifest 与每个 CA bundle 都通过 `securemanifest` 读取：

- 干净绝对路径；最终组件不跟随 symlink；
- 当前 euid 所有、单 hardlink、regular file；
- 不允许 group/world writable；
- ACL 或未知扩展属性拒绝；
- FD 内双读、元数据与内容稳定；
- Manifest 最大 1 MiB，严格 UTF-8/JSON，未知字段、转义重复字段和尾随文档拒绝。

CA bundle 另有更窄门禁：总计不超过 64 KiB、1–16 个根、每个 DER 不超过 16 KiB；每个证书
必须处于有效期、是具备 `CertSign` 的自签 CA，不能包含 private key、leaf、重复根或尾随垃圾。

Kubernetes ConfigMap/Secret projected volume 通常以 symlink 暴露，不能直接传给该 loader。
部署必须由受控 init container 把已验证输入复制到空 `emptyDir`，设置为业务进程 euid 所有、
单 hardlink、`0600` regular file，并在业务容器中只读挂载；不能放宽 loader 去兼容 symlink。

## TLS 与固定执行器 profile

Target 只接受小写、显式端口、无 userinfo/path/query/fragment 的 HTTPS DNS origin；拒绝 IP、
通配符、单标签名称和 percent encoding。返回的 TLS 配置只信任 manifest CA，固定 SNI、TLS 1.3
和 HTTP/1.1，禁用 session ticket、renegotiation 与 `InsecureSkipVerify`，且每次返回深拷贝。

`read-executor-profile.v1` 的摘要固定在二进制中，只声明两种操作：

- Prometheus `POST /api/v1/query_range`，参考[官方 HTTP API](https://prometheus.io/docs/prometheus/3.5/querying/api/)；
- VictoriaLogs `POST /select/logsql/query`，参考[官方查询 API](https://docs.victoriametrics.com/victorialogs/querying/)。

Profile 同时绑定无 proxy、redirect、cookie、compression、system roots，固定超时、32 KiB header
和 1 MiB response body 上限。M5C2-3a 只冻结这些事实；M5C2-3b 必须用本地 TLS 契约服务器证明
真实 HTTP transport 与严格响应解析逐项兑现，不能把 profile 声明当作执行证据。

## 生成、轮换与回滚

当前没有面向生产的 manifest CLI。受控构建工具必须调用 `readtarget.BuildTargetRef` 生成 ref，
随后把完整定义写入 owner-only 文件，再用同版本二进制执行 `LoadFile` 预检；禁止人工拼接摘要。

CA、endpoint、role 或 network policy 轮换采用 expand-first：

1. 生成并审查新制品引用；CA 过渡期可在同一 bundle 中同时放当前/下一根；
2. 生成新 TargetRef，并先发布包含新 target 的 manifest；
3. 生成引用新 TargetRef 的 connector 与 plan manifest；
4. 保留旧 binary/profile/manifest，直到其绑定的 Workflow、Task 和 attempt 全部终态；
5. 收缩旧 target 与旧根，再验证无活动 runtime binding 引用。

Manifest 没有热更新。失败时停止新进程并回到上一组相互匹配的 target/connector/plan 文件；
不能只回滚其中一层，也不能让旧/new READ Runner 混用同一 task queue。M5C2-3a 没有 live claim，
因此当前回滚不需要迁移或数据修复。

## 后续 Go/No-Go 门禁

M5C2-3b 至少要证明：固定 HTTP/1.1 transport、显式 DNS/IP allowlist 与 rebinding 防护、无 proxy/
redirect/cookie/compression、TLS/SNI/CA 失败矩阵、20 秒总超时、header/body 上限、严格
Prometheus matrix 与 VictoriaLogs JSON-lines 解析、部分结果拒绝、credential 只在单次 Execute
存活且不进入日志/trace/error。

M5C2-4 才能考虑装配配置、Worker、Outbox dispatcher、READ Runner Activity 和 Gateway callbacks。
在那之前还必须核验 role/network-policy 引用对应的真实制品、ServiceAccount/NetworkPolicy/egress
实际生效、PKI 轮换、Temporal replay 与本地端到端证据。任一门禁缺失时 READ claims 保持关闭。

本阶段不改变 `AIOPS_WRITE_EXECUTION_MODE=disabled|non-production`，不新增 production 值，
也不把调查结果连接到 ActionPlan、审批或 mutation adapter；生产写仍不存在可配置启用路径。
