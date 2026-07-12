# READ Target Runtime 运维契约

日期：2026-07-11
阶段：M5C2-3a/C2-3b/C2-4a（内容寻址 target、egress、atomic Bundle 与未装配的固定 READ HTTP executor；READ claims 关闭）

## 目的与边界

`internal/readtarget` 把一个 READ 数据源目标编译为进程内不可变能力，
`internal/readruntime` 再把 connector、target 与固定 executor profile 解析成三个服务端摘要。
Repository 只持久化这些摘要及自行计算的 aggregate runtime digest；Task、Runner 请求和
Temporal History 都不能提交或覆盖 endpoint、CA、query、credential、网络策略或摘要。

M5C2-3b 新增固定、进程内、one-shot READ HTTP executor，仅支持 Prometheus `range_query`
与 VictoriaLogs `search`。`Prepare` 不解析 DNS、不拨号、不取凭据，并把持久化 input hash、
connector/target/executor fences、精确 scope、target 与 egress policy 固定到一次性 capability；
只有独立 READ client 成功 `:start` 后签发的 opaque `StartCapability` 才能构造可信
`ExecutionStart`；其 epoch/scope revision 再次一致后，`Execute` 才能消费 Prepared 一次。
执行结果继续绑定同一 task/epoch/scope revision，并只生成 secret-free Completion；Fence 与 bearer
始终由同一个 READ client 的私有 Lease state 绑定，跨任务/attempt/scope 交换会 fail closed。

该 executor 尚未接入 `cmd/read-runner`、Worker、Gateway callbacks 或 Outbox dispatcher；本阶段
不新增 route、配置、迁移或 Activity 注册。Control Plane 现在使用单一关闭态 Admission，在数据库
与 authorizer 之前同时拒绝 Claim、Start、Heartbeat 和 Complete，因此旧 lease 也不能推进。

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

## 内容寻址 egress policy

`read-egress-policy.v1` 使用 JCS/SHA-256 固定以下服务端事实：

- 精确 Tenant、Workspace、Environment、DNS hostname 与显式端口；
- 最多 32 个 canonical、互不重叠的 CIDR；IPv4 不得宽于 `/24`，IPv6 不得宽于 `/64`；
- DNS 最多返回 16 个地址，去重前后的每个答案都必须命中 allowlist；
- special/non-unicast、IPv4/IPv6 link-local、multicast 及已知 AWS、GCP、Azure metadata 地址
  由二进制硬拒绝，不能通过 manifest 放宽；
- DNS 只解析一次并使用带尾点 hostname；随后仅拨 literal IP，并核对连接的实际
  `RemoteAddr` 与被允许的 IP/port，避免代理、搜索域和二次解析扩大目标。

Policy ref、scope、hostname、port 或任一 CIDR 漂移都会导致启动/`Prepare` 失败。Policy 本身
不携带 bearer、header 或 URL，也不能从 Task、Runner request 或 JSON 反序列化为运行时能力。

M5C2-4a 增加 owner-only `read-egress-policy-registry.v1` 文件与 immutable registry，并用
`read-runtime-bundle.v1` 原子校验每个 connector→target→policy→executor 依赖及四个 registry/profile
摘要。详见 [READ Runtime Bundle 与关闭态 Admission](read-runtime-bundle.md)。

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

当前审查 pin 为
`d776a2e45f33496a8a2558fba82096064c3aed10be588627a337e70983485e63`。Profile 与实现共同固定：

- TLS 1.3、HTTP/1.1、manifest 显式 CA 与精确 SNI；拒绝系统根、TLS callback、client cert、
  proxy、redirect、cookie、compression、connection reuse、retry、response trailer/content encoding；
- DNS/dial 5 秒、TLS handshake 5 秒、response header 10 秒、上游 query timeout 10 秒、总请求
  context 20 秒；request form 16 KiB、header 32 KiB、body 1 MiB。Go 不能强杀任意阻塞函数，
  因此 C2-4c 只能装配同步、服从 context 且对远端取凭据设置更短超时的可信 provider；
- DNS、provider 与 HTTP 前会剥离调用方全部 context values，避免 `httptrace`/trace hook 观察
  Authorization；严格 JSON 同时拒绝重复、未知、unsafe 及大小写折叠字段别名；
- Prometheus 仅接收成功 `matrix`，并拒绝非空 warnings/infos、native histogram、乱序/重复
  series、非 step-grid sample、预算溢出或部分结果；行为参考固定的 Prometheus 3.5 API 文档，
  该链接不是“最新版本”声明；
- VictoriaLogs 只接收严格 JSON-lines 与 canonical UTC `_time`，按 time 再按 JCS 确定性排序，
  严格执行 `[start,end)` 与字段/条数/投影预算；
- bearer 长度固定为 16–4096 bytes，只经同步 `BearerSource` callback 包住一次 `RoundTrip`
  及其有界 response projection。Executor 在 response headers 后移除 Authorization header，
  并在 callback 返回/provider 清零前对 canonical Evidence 做 credential contamination 检查；
  exact raw bearer 一旦被上游回显即整项失败且不生成 Evidence。Provider 仍必须在 callback
  返回后清理其 byte slice，不能宣称 executor 能销毁 provider 或 Go runtime 的所有副本。

本地真实 TLS 契约服务器与负向测试已逐项证明上述代码边界，但这不等价于企业 PKI、真实数据源
或集群 egress enforcement 验收。

## 生成、轮换与回滚

当前没有面向生产的 manifest CLI。受控构建工具必须调用 `readtarget.BuildTargetRef` 生成 ref，
随后把完整定义写入 owner-only 文件，再用同版本二进制执行 `LoadFile` 预检；禁止人工拼接摘要。

CA、endpoint、role 或 network policy 轮换采用 expand-first：

1. 生成并审查新制品引用；CA 过渡期可在同一 bundle 中同时放当前/下一根；
2. 生成新 TargetRef，并先发布包含新 target 的 manifest；
3. 生成引用新 TargetRef 的 connector 与 plan manifest；
4. 保留旧 binary/profile/manifest（包括 validator-v1 ConnectorID 兼容版本），直到其绑定的
   Workflow、Task 和 attempt 全部终态；
5. 收缩旧 target 与旧根，再验证无活动 runtime binding 引用。

Manifest 没有热更新。失败时停止新进程并回到上一组相互匹配的 connector/target/egress/plan 文件；
不能只回滚其中一层，也不能让旧/new READ Runner 混用同一 task queue。M5C2-3b 仍没有 live
claim/assembly，因此当前回滚不需要迁移或数据修复。

## 后续 Go/No-Go 门禁

C2-4a 的本地 TLS、Bundle 与负向测试只证明代码契约，不等价于企业 PKI、真实数据源、Vault role、
ServiceAccount、NetworkPolicy 或 egress enforcement 验收。C2-4b 已完成未装配的 Temporal v2 与 READ Runner
Activity；C2-4c 才负责原子装配配置、Worker、Gateway callbacks 与 Outbox dispatcher；还必须核验 component/profile digest 一致、PKI
轮换、Temporal replay、身份/网络边界、真实源侧脱敏/DLP 和本地 Signal→Evidence 端到端证据。
原文污染检查不能检测主动分片或再编码的 secret，不能替代源侧控制。即使完成装配，也只有
全部 Go/No-Go 证据通过后才能另行考虑 READ claims；任一门禁缺失时 claims 保持关闭。

本阶段不改变 `AIOPS_WRITE_EXECUTION_MODE=disabled|non-production`，不新增 production 值，
也不把调查结果连接到 ActionPlan、审批或 mutation adapter；生产写仍不存在可配置启用路径。
