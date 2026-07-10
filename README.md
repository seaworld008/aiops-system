# AIOps Control Plane

面向中小企业内部使用的证据驱动运维调查与受控执行平台。当前实现以 `AIOPS-IMPLEMENTATION-BLUEPRINT-2026-V3.md` 为权威输入。

## 开发要求

- Go 1.26.5（仓库 `toolchain` 会自动选择）
- PostgreSQL 16+（作用域完整性迁移使用生成列）
- 完整集成测试还需要 Temporal、Keycloak、Vault 和 S3 兼容对象存储

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

Alertmanager/夜莺 Webhook 必须携带 `X-AIOPS-Signature: sha256=<hex>`，签名内容为原始请求体的 HMAC-SHA256。开发环境可用 `AIOPS_WEBHOOK_HMAC_SECRET`；生产环境必须通过 `AIOPS_WEBHOOK_HMAC_SECRETS_JSON` 按 `integration_id/provider` 隔离，并配置 `AIOPS_DATABASE_URL`，否则控制面拒绝启动。数据库 Integration 记录再次校验 Workspace、Provider 和启停状态；后续 Vault 适配器会用其中的 `secret_ref` 替代环境变量密钥。

本机没有 PostgreSQL 时，迁移集成测试会跳过。可设置以下变量运行真实 PostgreSQL 16 的 up/down、作用域和 pgx 仓储测试：

```bash
AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' go test -count=1 ./internal/store/postgres
```

当前阶段已提供领域、信号接入和首批只读连接器；真实企业连接器必须使用各环境凭据配置，不随仓库分发。
