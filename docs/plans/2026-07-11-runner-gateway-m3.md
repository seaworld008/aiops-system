# Runner Gateway M3：mTLS 身份与分段执行协议

## 目标

在公共 API 之外提供独立的 TLS 1.3 Runner Gateway，把每次 Runner
操作绑定到客户端证书、SPIFFE URI、服务端注册、精确 scope revision、
lease epoch/token 和不可变结果回执。M3 不启动生产写，也不把任意命令、
Vault manager 能力或生产任务发给 Runner。

## 固定信任边界

- Go 进程直接终止 TLS；上游只能 TCP passthrough。
- Runner listener 与公共 listener 使用不同的 `http.Server` 和 Router。
- `tls.Config` 固定 TLS 1.3、`RequireAndVerifyClientCert`、显式 READ/WRITE
  Client CA、HTTP/1.1；不提供系统 CA、代理证书 header、CN fallback 或
  `InsecureSkipVerify` 配置。
- 客户端证书必须只有一个 URI SAN，且精确匹配
  `spiffe://<trust-domain>/runner/<read|write>/<instance>`。DNS/IP/Email SAN、
  URI 转义、userinfo、port、query、fragment、点段和空段均拒绝。
- READ/WRITE CA 根集合不得重叠。证书链 pool、URI pool 和数据库注册 pool
  必须一致。
- TLS 握手负责静态链和身份形状；每个 HTTP 请求无缓存查询证书、Runner、
  enabled、登记有效期和 scope revision；每个状态事务再次按相同证据
  `FOR SHARE` 重验，线性化 keepalive 上的吊销、禁用和 scope 收窄。
- 请求体、URL、query、cookie 和身份 header 不能提供 runner、pool、tenant、
  workspace、environment 或 scope。出现代理证书/Runner 身份 header 直接拒绝。
- 原始 job lease token 只由 `jobs:lease` 成功响应返回一次；原始 revocation
  claim token 只由 `revocations:lease` 返回一次。后续请求仅使用专用
  `Authorization` scheme，token 不进入 URL、body、日志、trace、audit 或数据库明文。

## v1 状态序列

### WRITE job

```text
jobs:lease
  -> LEASED
  -> start（最终复核 + PREPARED；一次性返回 child-create permit）
  -> RUNNING
  -> credential-anchor(AUTHORIZE_CHILD_CREATE)
  -> WRITE Runner 使用本地 Vault manager 创建 child
  -> credential-anchor(RECORD_ANCHOR) ACK
  -> WRITE Runner 使用 child 签发动态 Secret
  -> credential-anchor(ACTIVATE) ACK
  -> Runner 将 Secret 通过 M4 匿名 FD 传入 Executor并发送 GO
  -> heartbeat*
  -> complete（服务端 JCS/SHA-256 回执 + 原子请求凭据吊销）
  -> FINALIZING
  -> 凭据 REVOKED/NO_CREDENTIAL 后 Finalize
```

`:release` 只允许 `LEASED`，且由服务端选择固定 reason hash 和退避。`:start`
之后的任何模糊结果都必须终止 Executor 并 `complete` 为 `UNCERTAIN`；v1 不信任
Runner 声明“尚未 GO”。

Gateway 和公共 `cmd/control-plane` 永不持有 Vault manager 或 revoker 能力。`:start`
使用服务端非秘密 issuer policy mapping 创建 `PREPARED`，成功状态转换后只返回一次
Broker-owned child-create permit；响应丢失时不得重新签发 permit。WRITE Runner 在 M4
持有独立 manager 能力，并使用 `credential-anchor` 的封闭 phase 协议调用 Gateway：

```text
AUTHORIZE_CHILD_CREATE -> RECORD_ANCHOR -> ACTIVATE
                         \-> REQUEST_REVOCATION
PREPARED 失败 -> NO_CREDENTIAL
```

Runner 不能提交 issuer ID/revision、Vault URL/path/namespace/role、TTL、scope 或任意
请求参数；这些都来自 start 时冻结的服务端映射。`RECORD_ANCHOR` 是唯一携带
revoke-only accessor 的请求，必须获得持久 ACK 后 Runner 才能使用 child 签发动态
Secret。child token 和动态 Secret 永不经过 Gateway。任一 post-anchor 响应丢失都
必须请求持久吊销并视为不确定。

### Revocation job

```text
revocations:lease -> REVOKING -> heartbeat* -> complete(REVOKED|FAILED)
```

只允许登记了 `CREDENTIAL_REVOCATION` capability 的 WRITE Runner。失败请求仅含固定
failure code；重试延迟、full jitter、12 次/2 小时耗尽和 `MANUAL_REQUIRED` 由
Gateway/数据库决定，Runner 不能提交错误正文、重试时间或人工升级声明。

### READ job

M3 完成身份和协议，但在 M5 调查任务仓储就绪前 READ `jobs:lease` 固定返回 `204`。
不得把任意 payload 塞入现有写动作 `ActionEnvelope`。

## 数据库演进

新增 `000009_runner_gateway_mtls`，不修改已经合并的 `000007/000008`：

- Runner 证书元数据不可变，只允许 `ACTIVE -> REVOKED`；禁止删除、复活和 truncate。
- 证书登记时间必须有限、有序，并限制 issuer/key/serial/SPKI 的规范形状。
- Runner 注册增加显式、默认关闭的 credential revocation capability。
- Runner 结果回执升级为 `runner-result.v2`：证书指纹非空并进入服务端 canonical hash。
  v1 历史记录只为迁移兼容保留，M3 Gateway 永不创建 v1。
- revocation claim 增加递增 heartbeat sequence 和不可变 completion receipt，保证
  heartbeat 重放不续租、completion 精确重放幂等、冲突结果拒绝。
- destructive down 在 v2 回执、活动 Runner lease、活动 revocation claim 或 M3 审计/
  outbox 证据存在时拒绝。

因此原计划的 investigation migration 顺延为 `000010_investigation_runtime`；这是
保持已合并迁移不可变的必要调整。

## 实施切片

### M3A：证书身份和 TLS 底座

- `internal/runneridentity`：SPIFFE、证书证据、不可由 wire 构造的身份、TLS 配置。
- `internal/runneridentity/postgres`：每请求认证和事务内 revalidation。
- 配置采用全有或全无：独立地址、server cert/key、READ/WRITE CA、trust domain，以及
  采用独立 32-byte AES/HMAC 材料的私有 credential-protection keyring 文件。
- 完成迁移及真实 PostgreSQL 身份、吊销、轮换、scope revision 测试。

### M3B：Authenticated ActionQueue 和 job API

- 新增按 authenticated fence 读取可信 `ClaimedAction` 的仓储能力。
- 从 `execution.Service.RunNext` 提取 pre-start authorizer；`:start` 不能是裸 Queue.Start。
- Claim/Start/Heartbeat/Release/Complete 事务内重验证书。
- heartbeat/release 租期、extension、reason 和退避只由服务端注入。
- v2 receipt 绑定 action、plan、Runner、certificate、epoch、scope revision 和结构化结果。

### M3C：凭据、吊销 API 和双 listener 装配

- `credential-anchor` 暴露现有 credential Repository 的封闭远程阶段；Vault
  `DurableBroker` 与 manager capability 只在 M4 WRITE Runner 装配。
- Complete 与 exact `(action_id, lease_epoch)` 吊销意图同事务提交。
- Revocation lease/heartbeat/complete 使用既有持久状态机，加 sequence/receipt。
- 控制面预绑定两个 listener；任一初始化/serve 异常都会关闭另一个并退出。
- 本地生成双 CA、双 Runner 证书，覆盖同一 keepalive 吊销/禁用/scope 收窄 E2E。
- M3 的 control-plane 有意不注入最终 `StartAuthorizer`：identity 与持久吊销 API 可运行，
  但 job lease/start 继续 fail closed；M4 隔离执行路径完成后才允许注入该依赖。

## HTTP 合同

规范位于 `api/openapi/runner-v1.json`。所有对象拒绝未知与重复字段、尾随 JSON、
压缩正文和重复/带参数 Content-Type。两个 lease 请求/响应上限 256 KiB，其余 64 KiB；
持久结果 summary 仍受 16 KiB 更严限制。所有响应（含错误与 204）固定：

```text
Cache-Control: no-store
X-Content-Type-Options: nosniff
```

错误使用 RFC 9457 `application/problem+json`，只返回稳定 URN、低基数 code/detail 和
不透明 request-id instance，不包含 token、accessor、证书详情、SPIFFE、SQL 或上游正文。

## 验证出口

- TLS：无证书、错误 CA/EKU/SAN、TLS 1.2、多 SAN、CN-only、跨 pool、当前/下一证书。
- 即时吊销：同 keepalive 的第二请求在证书吊销/Runner 禁用后失败；scope 收窄后的
  heartbeat 返回 `TERMINATE` 且不续租。
- 并发：证书吊销、disable、scope bump 与 Claim/Start/Heartbeat/Complete 的锁序竞态。
- API：每个 POST 的未知/重复/尾随/超限/identity injection 负向用例。
- token/accessor/Secret canary 不进入数据库、日志、trace、audit、outbox 或错误。
- v2 receipt 任一绑定字段改变都会改变 hash；Runner 不能提交 result hash。
- 公共端口的 `/runner/v1/*` 与 Runner 端口的 `/api/v1/*` 均为 404。
- 固定全仓门禁、真实 PostgreSQL 16 和独立安全复审全部通过后才合并 M3。

生产写仍不存在可配置启用路径；`AIOPS_WRITE_EXECUTION_MODE` 继续只接受
`disabled|non-production`，Gateway 对 `production=true` 永不发放 lease。
