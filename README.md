# AIOps Control Plane

面向中小企业内部使用的证据驱动运维调查与受控执行平台。当前实现以 `AIOPS-IMPLEMENTATION-BLUEPRINT-2026-V3.md` 为权威输入。

## 开发要求

- Go 1.26.5（仓库 `toolchain` 会自动选择）
- 后续集成测试需要 PostgreSQL、Temporal、Keycloak、Vault 和 S3 兼容对象存储

## 本地命令

```bash
make test
make vet
make build
make run
```

启动后可访问：

```text
GET http://localhost:8080/healthz
GET http://localhost:8080/readyz
```

Alertmanager/夜莺 Webhook 必须携带 `X-AIOPS-Signature: sha256=<hex>`，签名内容为原始请求体的 HMAC-SHA256。开发环境通过 `AIOPS_WEBHOOK_HMAC_SECRET` 注入测试密钥；生产环境缺少该配置时控制面拒绝启动。后续生产适配器会把密钥解析切换到按 Integration 隔离的 Vault 引用。

当前阶段已提供领域、信号接入和首批只读连接器；真实企业连接器必须使用各环境凭据配置，不随仓库分发。
